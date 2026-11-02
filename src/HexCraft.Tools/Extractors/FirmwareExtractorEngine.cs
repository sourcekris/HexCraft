using System.Text;
using HexCraft.Tools.Signatures;

namespace HexCraft.Tools.Extractors;

/// <summary>
/// Result returned by an internal <see cref="IFirmwareExtractor"/> after unpacking a carved payload.
/// </summary>
public sealed record ExtractorExecutionResult(
    bool Success,
    string ExtractorId,
    IReadOnlyList<string> ExtractedFiles,
    string LogMessage,
    bool SupportsRecursion = true);

/// <summary>
/// Pluggable interface for native in-memory firmware extractors modeled after
/// Binwalk v3's <c>src/extractors/</c> architecture.
/// </summary>
public interface IFirmwareExtractor
{
    /// <summary>Short unique identifier (e.g., "cramfs", "romfs", "dtb", "uimage", "trx").</summary>
    string Id { get; }

    /// <summary>Human-readable extractor name.</summary>
    string Name { get; }

    /// <summary>
    /// Determines whether this extractor can unpack the given signature or payload header.
    /// </summary>
    bool CanExtract(string signatureId, string signatureType, ReadOnlySpan<byte> payload);

    /// <summary>
    /// Unpacks the binary <paramref name="payload"/> into <paramref name="outputDirectory"/>.
    /// </summary>
    ExtractorExecutionResult Extract(ReadOnlySpan<byte> payload, string outputDirectory);
}

/// <summary>
/// Registry and execution pipeline for native firmware extractors, including
/// path-traversal sanitization and optional Matryoshka recursive extraction.
/// </summary>
public sealed class FirmwareExtractorRegistry
{
    private readonly List<IFirmwareExtractor> _extractors = new();

    public IReadOnlyList<IFirmwareExtractor> Extractors => _extractors;

    public void Register(IFirmwareExtractor extractor)
    {
        ArgumentNullException.ThrowIfNull(extractor);
        _extractors.RemoveAll(e => string.Equals(e.Id, extractor.Id, StringComparison.OrdinalIgnoreCase));
        _extractors.Add(extractor);
    }

    public static FirmwareExtractorRegistry CreateDefault()
    {
        var registry = new FirmwareExtractorRegistry();
        foreach (var extractor in BuiltinFirmwareExtractors.All)
        {
            registry.Register(extractor);
        }
        foreach (var extractor in IdArcFirmwareExtractors.All)
        {
            registry.Register(extractor);
        }
        return registry;
    }

    /// <summary>
    /// Finds a matching extractor and unpacks <paramref name="payload"/> into <paramref name="outputDirectory"/>.
    /// When <paramref name="recursiveScanner"/> is provided, performs Matryoshka recursive extraction on
    /// newly unpacked binary containers up to <paramref name="maxRecursionDepth"/>.
    /// </summary>
    public ExtractorExecutionResult ExtractPayload(
        ReadOnlySpan<byte> payload,
        string signatureId,
        string signatureType,
        string outputDirectory,
        FirmwareSignatureRegistry? recursiveScanner = null,
        int maxRecursionDepth = 2)
    {
        Directory.CreateDirectory(outputDirectory);
        var allExtractedFiles = new List<string>();
        var log = new StringBuilder();

        IFirmwareExtractor? matched = _extractors.FirstOrDefault(
            e => string.Equals(e.Id, signatureId, StringComparison.OrdinalIgnoreCase));

        if (matched is null)
        {
            foreach (var extractor in _extractors)
            {
                if (extractor.CanExtract(signatureId, signatureType, payload))
                {
                    matched = extractor;
                    break;
                }
            }
        }

        if (matched is null)
        {
            return new ExtractorExecutionResult(
                Success: false,
                ExtractorId: "none",
                ExtractedFiles: Array.Empty<string>(),
                LogMessage: $"[i] No native unpacker registered for '{signatureType}' (raw binary carved).");
        }

        var result = matched.Extract(payload, outputDirectory);
        log.AppendLine(result.LogMessage.TrimEnd());
        allExtractedFiles.AddRange(result.ExtractedFiles);

        // Matryoshka recursive extraction on newly unpacked .bin payloads
        if (result.Success && result.SupportsRecursion && recursiveScanner is not null && maxRecursionDepth > 0)
        {
            foreach (string childFile in result.ExtractedFiles.ToList())
            {
                if (!childFile.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) || !File.Exists(childFile))
                    continue;

                byte[] childBytes = File.ReadAllBytes(childFile);
                if (childBytes.Length < 16)
                    continue;

                var childHits = recursiveScanner.Scan(childBytes);
                foreach (var hit in childHits)
                {
                    if (hit.Offset < 0 || hit.Offset >= childBytes.Length)
                        continue;

                    int sliceLen = hit.EstimatedSize > 0 && hit.Offset + hit.EstimatedSize <= childBytes.Length
                        ? (int)hit.EstimatedSize
                        : (int)(childBytes.Length - hit.Offset);

                    string hitSigId = hit.SourceEngine.Contains('.')
                        ? hit.SourceEngine.Split('.')[^1]
                        : (hit.SourceEngine.Contains(':') ? hit.SourceEngine.Split(':')[^1] : hit.SignatureType);

                    string subDir = Path.Combine(
                        outputDirectory,
                        $"{Path.GetFileNameWithoutExtension(childFile)}_{hitSigId}_{hit.Offset:X}");

                    var subResult = ExtractPayload(
                        childBytes.AsSpan((int)hit.Offset, sliceLen),
                        hitSigId,
                        hit.SignatureType,
                        subDir,
                        recursiveScanner,
                        maxRecursionDepth - 1);

                    if (subResult.Success && subResult.ExtractedFiles.Count > 0)
                    {
                        log.AppendLine($"[+] Matryoshka Recursive Unpack ({hit.SignatureType} @ +0x{hit.Offset:X}):");
                        log.AppendLine(subResult.LogMessage.TrimEnd());
                        allExtractedFiles.AddRange(subResult.ExtractedFiles);
                    }
                }
            }
        }

        return new ExtractorExecutionResult(
            Success: result.Success,
            ExtractorId: matched.Id,
            ExtractedFiles: allExtractedFiles,
            LogMessage: log.ToString().TrimEnd());
    }

    /// <summary>
    /// Sanitizes an archive/filesystem relative path against directory traversal (".."),
    /// absolute roots, and invalid characters (similar to Binwalk v3's <c>Chroot</c> helper).
    /// </summary>
    public static string SanitizeSafeOutputPath(string rootOutputDir, string relativeArchivePath)
    {
        string fullRoot = Path.GetFullPath(rootOutputDir);
        string normalized = relativeArchivePath.Replace('\\', '/').Trim('/');

        var safeSegments = new List<string>();
        foreach (string rawSeg in normalized.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (rawSeg == "." || rawSeg == "..")
                continue;

            var sb = new StringBuilder(rawSeg.Length);
            foreach (char c in rawSeg)
            {
                sb.Append(Path.GetInvalidFileNameChars().Contains(c) ? '_' : c);
            }
            string clean = sb.ToString().Trim();
            if (!string.IsNullOrEmpty(clean) && clean != "." && clean != "..")
                safeSegments.Add(clean);
        }

        if (safeSegments.Count == 0)
            safeSegments.Add("unnamed_entry");

        string combined = Path.GetFullPath(Path.Combine(new[] { fullRoot }.Concat(safeSegments).ToArray()));
        if (!combined.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
            return Path.Combine(fullRoot, safeSegments[^1]);

        return combined;
    }
}

