using System;
using System.Collections.Generic;
using System.Linq;
using HexCraft.Core.Buffers;

namespace HexCraft.Tools.Signatures;

public enum SignatureConfidence
{
    Low = 1,
    Medium = 2,
    High = 3
}

/// <summary>
/// Result returned by an <see cref="IFirmwareSignatureParser"/> when a magic pattern
/// is structurally validated at a given offset.
/// </summary>
public sealed record SignatureParseResult(
    bool IsValid,
    string Description = "",
    long EstimatedSize = 0,
    SignatureConfidence Confidence = SignatureConfidence.High,
    bool CanUnsquashfs = false)
{
    public static SignatureParseResult Invalid => new(false);
}

/// <summary>
/// Extensible plugin contract modeled after ReFirmLabs/binwalk v3 (`src/signatures/*.rs`).
/// Each signature module defines one or more magic byte patterns and a structural parser
/// that validates candidate offsets to eliminate false positives and calculate exact payload sizes.
/// </summary>
public interface IFirmwareSignatureParser
{
    /// <summary>Short identifier (e.g. "squashfs", "uimage", "dtb", "gzip").</summary>
    string Name { get; }

    /// <summary>Human-readable display title (e.g. "SquashFS Filesystem", "U-Boot uImage").</summary>
    string DisplayName { get; }

    /// <summary>Category (e.g. "Filesystem", "Firmware Header", "Compressed", "Archive", "Crypto").</summary>
    string Category { get; }

    /// <summary>One or more magic byte sequences that trigger this parser.</summary>
    IReadOnlyList<byte[]> MagicPatterns { get; }

    /// <summary>
    /// Validates the header at <paramref name="offset"/> inside <paramref name="fullData"/>
    /// and returns a structured <see cref="SignatureParseResult"/>.
    /// </summary>
    SignatureParseResult Parse(ReadOnlySpan<byte> fullData, int offset);
}

/// <summary>
/// Extensible registry and multi-pattern scanning engine for HexCraft's internal Binwalk-style
/// firmware analysis library.
/// </summary>
public sealed class FirmwareSignatureRegistry
{
    private readonly List<IFirmwareSignatureParser> _parsers = new();

    public IReadOnlyList<IFirmwareSignatureParser> Parsers => _parsers;

    public static FirmwareSignatureRegistry CreateDefault()
    {
        var registry = new FirmwareSignatureRegistry();
        foreach (var parser in BuiltinSignatureParsers.CreateAll())
        {
            registry.Register(parser);
        }
        foreach (var parser in ExtendedSignatureParsers.CreateAll())
        {
            registry.Register(parser);
        }
        foreach (var parser in IdArcSignatureParsers.CreateAll())
        {
            registry.Register(parser);
        }
        return registry;
    }

    public void Register(IFirmwareSignatureParser parser)
    {
        ArgumentNullException.ThrowIfNull(parser);
        _parsers.Add(parser);
    }

    public List<FirmwareSignatureEntry> Scan(BinaryDocument doc, long maxBytesToScan = 64L * 1024 * 1024)
    {
        var results = new List<FirmwareSignatureEntry>();
        long scanLen = Math.Min(doc.Length, maxBytesToScan);
        if (scanLen <= 0)
            return results;

        byte[] data = doc.ReadBytes(0, (int)scanLen);
        return Scan(data, doc.Length);
    }

    public List<FirmwareSignatureEntry> Scan(ReadOnlySpan<byte> data, long totalDocumentLength = -1)
    {
        if (totalDocumentLength < 0)
            totalDocumentLength = data.Length;

        var results = new List<FirmwareSignatureEntry>();

        foreach (var parser in _parsers)
        {
            foreach (byte[] magic in parser.MagicPatterns)
            {
                if (magic is null || magic.Length == 0 || data.Length < magic.Length)
                    continue;

                ReadOnlySpan<byte> magicSpan = magic;
                int pos = 0;

                while (pos <= data.Length - magicSpan.Length)
                {
                    int relIdx = data[pos..].IndexOf(magicSpan);
                    if (relIdx < 0)
                        break;

                    int matchOffset = pos + relIdx;
                    var parsed = parser.Parse(data, matchOffset);

                    if (parsed.IsValid && !string.IsNullOrEmpty(parsed.Description))
                    {
                        long clampedSize = parsed.EstimatedSize > 0
                            ? Math.Min(parsed.EstimatedSize, totalDocumentLength - matchOffset)
                            : 0;

                        // Avoid duplicate hits from overlapping magic patterns of the same parser at the same offset
                        if (!results.Any(r => r.Offset == matchOffset && r.SignatureType == parser.DisplayName))
                        {
                            results.Add(new FirmwareSignatureEntry(
                                Offset: matchOffset,
                                EstimatedSize: clampedSize,
                                SignatureType: parser.DisplayName,
                                Category: parser.Category,
                                Description: parsed.Description,
                                CanUnsquashfs: parsed.CanUnsquashfs,
                                SourceEngine: $"HexCraft.{parser.Name}"));
                        }

                        // Advance past magic
                        pos = matchOffset + Math.Max(1, magicSpan.Length);
                    }
                    else
                    {
                        pos = matchOffset + 1;
                    }
                }
            }
        }

        results.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        return results;
    }
}

