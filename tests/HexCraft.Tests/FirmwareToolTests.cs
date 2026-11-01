using System.IO;
using System.Linq;
using System.Text;
using HexCraft.Core.Analysis;
using HexCraft.Core.Buffers;
using HexCraft.Tools;
using Xunit;

namespace HexCraft.Tests;

public class FirmwareToolTests
{
    [Fact]
    public void BuiltinSignatureScanner_Detects_Png_SquashFs_And_Gzip_In_Firmware_Blob()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "firmware_test.bin");

        var entries = FirmwareToolService.ScanSignatures(doc, tryExternalBinwalk: false);

        Assert.Contains(entries, e => e.SignatureType == "PNG Image" && e.Offset == 0);
        Assert.Contains(entries, e => e.SignatureType == "SquashFS (LE)" && e.Offset == 0x1E0 && e.CanUnsquashfs);
        Assert.Contains(entries, e => e.SignatureType == "GZip Stream" && e.Offset == 0x260);
    }

    [Fact]
    public void CarveAndExtract_Decompresses_Embedded_Gzip_Stream_Automatically()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "firmware_test.bin");

        var entries = FirmwareToolService.ScanSignatures(doc, tryExternalBinwalk: false);
        var gzipEntry = entries.First(e => e.SignatureType == "GZip Stream");

        var outcome = FirmwareToolService.CarveAndExtractAsync(doc, gzipEntry).GetAwaiter().GetResult();

        Assert.True(outcome.Success);
        var decompFile = outcome.ExtractedFiles.FirstOrDefault(f => f.Contains("decompressed_"));
        Assert.NotNull(decompFile);

        string decompText = File.ReadAllText(decompFile!);
        Assert.Contains("HexCraft Embedded Initramfs Script", decompText);
    }

    [Fact]
    public void ByteOperations_Xor_Invert_Reverse_And_CopyAsCode_Work()
    {
        byte[] raw = { 0x10, 0x20, 0x30, 0x40 };
        using var doc = new BinaryDocument(raw);

        ByteOperations.XorRange(doc, 0, 4, new byte[] { 0xFF });
        Assert.Equal(new byte[] { 0xEF, 0xDF, 0xCF, 0xBF }, doc.ReadBytes(0, 4));

        ByteOperations.InvertRange(doc, 0, 4);
        Assert.Equal(new byte[] { 0x10, 0x20, 0x30, 0x40 }, doc.ReadBytes(0, 4));

        ByteOperations.ReverseRange(doc, 0, 4);
        Assert.Equal(new byte[] { 0x40, 0x30, 0x20, 0x10 }, doc.ReadBytes(0, 4));

        string cCode = ByteOperations.FormatBytesAsCode(doc.ReadBytes(0, 4), CopyExportFormat.CArray, "shellcode");
        Assert.Contains("const uint8_t shellcode[4]", cCode);
        Assert.Contains("0x40, 0x30, 0x20, 0x10", cCode);
    }

    [Fact]
    public void WslPathConverter_Translates_Windows_Drive_Path_Correctly()
    {
        string wsl = FirmwareToolService.ConvertWindowsPathToWsl(@"C:\Workspaces\HexCraft\firmware.bin");
        Assert.Equal("/mnt/c/Workspaces/HexCraft/firmware.bin", wsl);
    }
}

