using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HexCraft.Templates;

public sealed record BinaryTemplateDefinition(
    string FileName,
    string DisplayName,
    string Description,
    string SourceCode,
    string? FilePath = null);

/// <summary>
/// Provides access to bundled 010 Editor Binary Templates (.bt) as well as loading custom .bt files from disk.
/// </summary>
public static class TemplateRepository
{
    public static IReadOnlyList<BinaryTemplateDefinition> GetAvailableTemplates(string? templatesDirectory = null)
    {
        var list = new List<BinaryTemplateDefinition>();
        string? dir = templatesDirectory ?? FindTemplatesDirectory();

        if (dir is not null && Directory.Exists(dir))
        {
            foreach (string file in Directory.GetFiles(dir, "*.bt").OrderBy(f => f))
            {
                string fileName = Path.GetFileName(file);
                string code = File.ReadAllText(file);
                string desc = ExtractPurposeComment(code) ?? $"010 Binary Template ({fileName})";
                list.Add(new BinaryTemplateDefinition(
                    FileName: fileName,
                    DisplayName: $"{Path.GetFileNameWithoutExtension(file)} ({fileName})",
                    Description: desc,
                    SourceCode: code,
                    FilePath: file));
            }
        }

        if (list.Count == 0)
        {
            // Fallback built-in defaults if running outside workspace directory
            list.Add(new BinaryTemplateDefinition(
                "PNG.bt",
                "PNG Image (PNG.bt)",
                "Parses PNG signature and chunks (IHDR, tEXt, IDAT, IEND).",
                DefaultPngTemplate));
            list.Add(new BinaryTemplateDefinition(
                "SquashFS.bt",
                "SquashFS Superblock (SquashFS.bt)",
                "Parses SquashFS v4.0 Little Endian Superblocks (including embedded firmware offsets).",
                DefaultSquashFsTemplate));
        }

        return list;
    }

    public static string? FindTemplatesDirectory()
    {
        string current = AppContext.BaseDirectory;
        for (int i = 0; i < 6; i++)
        {
            string candidate = Path.Combine(current, "templates");
            if (Directory.Exists(candidate))
                return candidate;
            var parent = Directory.GetParent(current);
            if (parent is null) break;
            current = parent.FullName;
        }

        if (Directory.Exists("templates"))
            return Path.GetFullPath("templates");

        return null;
    }

    private static string? ExtractPurposeComment(string code)
    {
        foreach (string line in code.Split('\n'))
        {
            int idx = line.IndexOf("Purpose:", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
                return line[(idx + 8)..].Trim();
        }
        return null;
    }

    private const string DefaultPngTemplate = """
        BigEndian();
        struct PNG_SIGNATURE {
            uchar magic[8] <bgcolor=cLtPurple, comment="PNG Signature">;
        };
        struct PNG_CHUNK {
            uint32 length <bgcolor=cLtYellow>;
            char type[4] <bgcolor=cLtBlue>;
            if (length > 0) uchar data[length] <bgcolor=cSilver>;
            uint32 crc32 <format=hex, bgcolor=cLtRed>;
        };
        PNG_SIGNATURE signature;
        while (!FEof()) {
            PNG_CHUNK chunk;
            if (chunk.type == "IEND") break;
        }
        """;

    private const string DefaultSquashFsTemplate = """
        LittleEndian();
        struct SQUASHFS_SUPERBLOCK {
            char s_magic[4] <bgcolor=cLtPurple>;
            uint32 inodes <bgcolor=cLtGreen>;
            time_t mkfs_time <bgcolor=cLtYellow>;
            uint32 block_size <bgcolor=cLtBlue>;
            uint32 fragments <bgcolor=cLtGreen>;
            ushort compression <bgcolor=cLtAqua>;
            ushort block_log;
            ushort flags <format=hex>;
            ushort no_ids;
            ushort s_major;
            ushort s_minor;
            uint64 root_inode <format=hex>;
            uint64 bytes_used <bgcolor=cLtGreen>;
        };
        SQUASHFS_SUPERBLOCK superblock;
        """;
}

