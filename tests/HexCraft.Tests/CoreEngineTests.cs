using System;
using System.IO;
using System.Linq;
using System.Text;
using HexCraft.Core.Analysis;
using HexCraft.Core.Buffers;
using Xunit;

namespace HexCraft.Tests;

public class CoreEngineTests
{
    [Fact]
    public void PieceTable_Overwrite_Insert_Delete_Undo_Redo_Works()
    {
        byte[] initial = Encoding.ASCII.GetBytes("HELLO_WORLD");
        using var doc = new BinaryDocument(initial);

        Assert.Equal(11, doc.Length);
        Assert.False(doc.IsModified);

        // Overwrite '_' with '-'
        doc.WriteByte(5, (byte)'-');
        Assert.True(doc.IsModified);
        Assert.Equal("HELLO-WORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));

        // Insert "123" at index 5
        doc.InsertBytes(5, Encoding.ASCII.GetBytes("123"));
        Assert.Equal(14, doc.Length);
        Assert.Equal("HELLO123-WORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));

        // Delete "123-" (4 bytes at index 5)
        doc.DeleteBytes(5, 4);
        Assert.Equal(10, doc.Length);
        Assert.Equal("HELLOWORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));

        // Undo delete
        doc.Undo();
        Assert.Equal("HELLO123-WORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));

        // Undo insert
        doc.Undo();
        Assert.Equal("HELLO-WORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));

        // Undo overwrite
        doc.Undo();
        Assert.Equal("HELLO_WORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));
        Assert.False(doc.IsModified);

        // Redo overwrite
        doc.Redo();
        Assert.Equal("HELLO-WORLD", Encoding.ASCII.GetString(doc.ReadBytes(0, (int)doc.Length)));
    }

    [Fact]
    public void FileAnalyzer_Identifies_PNG_And_Computes_Hashes()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "firmware_sample.bin");

        var report = FileAnalyzer.Analyze(doc);

        Assert.NotEmpty(report.MagicMatches);
        Assert.Contains(report.MagicMatches, m => m.FormatName.Contains("PNG") && m.RecommendedTemplate == "PNG.bt");
        Assert.NotEmpty(report.ExifAndFormatTags);
        Assert.Contains(report.ExifAndFormatTags, t => t.TagName == "Make" && t.Value.Contains("HexCraft Embedded Labs"));
        Assert.Contains(report.ExifAndFormatTags, t => t.TagName == "Model" && t.Value.Contains("GL-MT6000"));
        Assert.Contains(report.ExifAndFormatTags, t => t.Group == "PNG:tEXt" && t.TagName == "Software");
        Assert.Equal(8, report.Crc32Hex.Length);
        Assert.Equal(32, report.Md5Hex.Length);
        Assert.Equal(64, report.Sha256Hex.Length);
        Assert.True(report.OverallEntropy > 1.0 && report.OverallEntropy < 8.0);
    }

    [Fact]
    public void StringsScanner_Extracts_Ascii_And_Utf16_Strings()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample);

        var strings = StringsScanner.Scan(doc, new StringScanOptions(MinCharacters: 5, IncludeAscii: true, IncludeUtf16Le: true));

        Assert.Contains(strings, s => s.Value.Contains("gl-mt6000-flint2"));
        Assert.Contains(strings, s => s.Value.Contains("Linux-6.6.32-arm64"));
        Assert.Contains(strings, s => s.Encoding == ExtractedStringEncoding.Utf16LittleEndian && s.Value.Contains("HexCraft_Reverse_Engineering_Suite"));
    }

    [Fact]
    public void DataInspector_Decodes_Little_And_Big_Endian()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample);

        // At offset 16 in PNG IHDR is Width = 512 (0x00000200 Big Endian)
        var beEntries = DataInspectorDecoder.DecodeAt(doc, 16, bigEndian: true);
        var u32Entry = beEntries.First(e => e.TypeName == "UInt32");
        Assert.Contains("512", u32Entry.ValueText);
    }
}

