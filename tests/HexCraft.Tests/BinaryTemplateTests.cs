using System;
using System.IO;
using System.Linq;
using System.Text;
using HexCraft.Core.Analysis;
using HexCraft.Core.Buffers;
using HexCraft.Templates;
using HexCraft.Templates.Evaluation;
using Xunit;

namespace HexCraft.Tests;

public class BinaryTemplateTests
{
    [Fact]
    public void PngTemplate_Parses_Chunks_And_Generates_ColorIntervals()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "sample.png");

        var templates = TemplateRepository.GetAvailableTemplates();
        var pngTemplate = templates.First(t => t.FileName == "PNG.bt");

        var result = BtInterpreter.Execute(doc, pngTemplate.SourceCode);

        Assert.True(result.Success, result.ErrorMessage ?? "");
        Assert.NotEmpty(result.RootNodes);
        Assert.Equal("signature", result.RootNodes[0].Name);

        // Expect 4 chunks: IHDR, tEXt, eXIf, IEND
        var chunks = result.RootNodes.Where(n => n.Name == "chunk").ToList();
        Assert.Equal(4, chunks.Count);

        var ihdrChunk = chunks[0];
        var ihdrStruct = ihdrChunk.Children.First(c => c.Name == "ihdr");
        var widthNode = ihdrStruct.Children.First(c => c.Name == "width");
        var heightNode = ihdrStruct.Children.First(c => c.Name == "height");
        Assert.Contains("512", widthNode.DisplayValue);
        Assert.Contains("256", heightNode.DisplayValue);

        Assert.NotEmpty(result.ColorIntervals);
        Assert.Contains(result.ConsoleOutput, line => line.Contains("Parsed PNG successfully"));
    }

    [Fact]
    public void SquashFsTemplate_Finds_And_Parses_Embedded_Superblock()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "firmware.bin");

        var templates = TemplateRepository.GetAvailableTemplates();
        var sqshTemplate = templates.First(t => t.FileName == "SquashFS.bt");

        var result = BtInterpreter.Execute(doc, sqshTemplate.SourceCode);

        Assert.True(result.Success, result.ErrorMessage ?? "");
        var sbNode = result.RootNodes.First(n => n.Name == "superblock");
        Assert.Equal(0x1E0, sbNode.StartOffset);

        var inodesNode = sbNode.Children.First(c => c.Name == "inodes");
        var compNode = sbNode.Children.First(c => c.Name == "compression");
        Assert.Contains("1428", inodesNode.DisplayValue);
        Assert.Contains("XZ_COMPRESSION", compNode.DisplayValue);
    }

    [Fact]
    public void CustomTemplate_Supports_Bitfields_Unions_Functions_And_Preprocessor()
    {
        const string btCode = """
            #define MAGIC_EXPECTED 0xCAFE
            LittleEndian();

            int AddValues(int a, int b) {
                return a + b;
            }

            union OVERLAY {
                ushort raw16 <format=hex>;
                uchar bytes[2];
            };

            struct HEADER {
                ushort magic <format=hex, bgcolor=cLtGreen>;
                uchar lowNib : 4 <bgcolor=cLtBlue>;
                uchar highNib : 4 <bgcolor=cLtYellow>;
                OVERLAY u;
            };

            HEADER hdr;
            local int sum = AddValues(hdr.lowNib, hdr.highNib);
            if (hdr.magic == MAGIC_EXPECTED) {
                Printf("Magic OK, nibbles sum=%d\n", sum);
            }
            """;

        byte[] payload = { 0xFE, 0xCA, 0xA5, 0x11, 0x22 };
        using var doc = new BinaryDocument(payload);

        var res = BtInterpreter.Execute(doc, btCode);

        Assert.True(res.Success, res.ErrorMessage ?? "");
        Assert.Single(res.RootNodes);
        var hdr = res.RootNodes[0];
        Assert.Equal(5, hdr.ByteLength);
        Assert.Contains(res.ConsoleOutput, l => l.Contains("Magic OK, nibbles sum=15"));
    }
}

