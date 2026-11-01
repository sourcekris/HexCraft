using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace HexCraft.Core.Analysis;

/// <summary>
/// Generates synthetic sample binary payloads (PNG + embedded SquashFS + strings + ZIP footer)
/// for testing and interactive demonstration in HexCraft.
/// </summary>
public static class SampleBinaryFactory
{
    public static byte[] CreateDemoFirmwareBlob()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        // 1. Valid PNG Header (0x00..0x21)
        bw.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }); // PNG signature
        // IHDR chunk length (13 BE)
        bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x0D });
        bw.Write(Encoding.ASCII.GetBytes("IHDR"));
        bw.Write(new byte[] { 0x00, 0x00, 0x02, 0x00 }); // Width = 512 BE
        bw.Write(new byte[] { 0x00, 0x00, 0x01, 0x00 }); // Height = 256 BE
        bw.Write((byte)8);  // Bit depth = 8
        bw.Write((byte)6);  // Color type = RGBA
        bw.Write((byte)0);  // Compression
        bw.Write((byte)0);  // Filter
        bw.Write((byte)0);  // Interlace
        bw.Write(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }); // CRC32 placeholder

        // tEXt chunk with metadata string
        byte[] textPayload = Encoding.ASCII.GetBytes("Software\0HexCraft Firmware Image v1.0.4-rc2 (Linux/Win11)");
        WriteBE32(bw, (uint)textPayload.Length);
        bw.Write(Encoding.ASCII.GetBytes("tEXt"));
        bw.Write(textPayload);
        bw.Write(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }); // CRC

        // eXIf chunk with real Little-Endian TIFF IFD0 (Make, Model, DateTimeOriginal)
        byte[] exifTiff = CreateSampleTiffExifPayload();
        WriteBE32(bw, (uint)exifTiff.Length);
        bw.Write(Encoding.ASCII.GetBytes("eXIf"));
        bw.Write(exifTiff);
        bw.Write(new byte[] { 0x11, 0x22, 0x33, 0x44 }); // CRC

        // IEND chunk
        bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 });
        bw.Write(Encoding.ASCII.GetBytes("IEND"));
        bw.Write(new byte[] { 0xAE, 0x42, 0x60, 0x82 });

        // Pad to offset 0xF0
        while (ms.Position < 0xF0)
            bw.Write((byte)0x00);

        // 2. Embedded Firmware Manifest & Strings
        bw.Write(Encoding.ASCII.GetBytes("HEXCRAFT_FW_MANIFEST\0"));
        bw.Write(Encoding.ASCII.GetBytes("board=gl-mt6000-flint2\0"));
        bw.Write(Encoding.ASCII.GetBytes("kernel=Linux-6.6.32-arm64\0"));
        bw.Write(Encoding.ASCII.GetBytes("rootfs=/dev/mtdblock4 (squashfs,xz)\0"));
        bw.Write(Encoding.ASCII.GetBytes("default_gateway=192.168.1.1:8080\0"));
        bw.Write(Encoding.Unicode.GetBytes("UTF16_KEY=HexCraft_Reverse_Engineering_Suite\0"));

        while (ms.Position < 0x1E0)
            bw.Write((byte)0xFF);

        // 3. Embedded SquashFS v4.0 Little Endian Superblock at 0x1E0
        bw.Write(Encoding.ASCII.GetBytes("hsqs"));        // s_magic (0x73717368)
        bw.Write((uint)1428);                             // inodes
        bw.Write((uint)1730380800);                       // mkfs_time (2024-10-31 UTC)
        bw.Write((uint)131072);                           // block_size (128 KB)
        bw.Write((uint)42);                               // fragments
        bw.Write((ushort)4);                              // compression (4 = XZ)
        bw.Write((ushort)17);                             // block_log
        bw.Write((ushort)0x00C0);                         // flags
        bw.Write((ushort)4);                              // no_ids
        bw.Write((ushort)4);                              // s_major (4)
        bw.Write((ushort)0);                              // s_minor (0)
        bw.Write((ulong)0x00001240);                      // root_inode
        bw.Write((ulong)4096);                            // bytes_used
        bw.Write((ulong)0x00000800);                      // id_table_start
        bw.Write((ulong)0xFFFFFFFFFFFFFFFFUL);            // xattr_id_table_start
        bw.Write((ulong)0x00000400);                      // inode_table_start
        bw.Write((ulong)0x00000500);                      // directory_table_start
        bw.Write((ulong)0x00000600);                      // fragment_table_start
        bw.Write((ulong)0x00000700);                      // lookup_table_start

        while (ms.Position < 0x260)
            bw.Write((byte)0x00);

        // 4. Real Decompressible GZip stream at 0x260
        byte[] gzipBytes = CreateEmbeddedGzipStream(
            "#!/bin/sh\n# HexCraft Embedded Initramfs Script\nmount -t proc proc /proc\nmount -t sysfs sys /sys\necho \"HexCraft router firmware booted on /dev/mtdblock4\"\n");
        bw.Write(gzipBytes);

        // Pad to 0x310
        while (ms.Position < 0x310)
            bw.Write((byte)0x00);

        // 5. Pseudo-encrypted high-entropy block
        var rng = new Random(0x48455843);
        byte[] highEntropy = new byte[128];
        rng.NextBytes(highEntropy);
        bw.Write(highEntropy);

        return ms.ToArray();
    }

    private static byte[] CreateSampleTiffExifPayload()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        // TIFF Header (8 bytes): Little Endian 'II', magic 42, IFD0 at offset 8
        bw.Write((byte)'I');
        bw.Write((byte)'I');
        bw.Write((ushort)42);
        bw.Write((uint)8);

        // IFD0: 3 entries (2 + 3*12 + 4 = 42 bytes -> string values start at offset 50)
        bw.Write((ushort)3);

        byte[] makeBytes = Encoding.ASCII.GetBytes("HexCraft Embedded Labs\0");
        byte[] modelBytes = Encoding.ASCII.GetBytes("GL-MT6000 Security Gateway\0");
        byte[] dateBytes = Encoding.ASCII.GetBytes("2026:11:01 12:30:00\0");

        uint makeOff = 50;
        uint modelOff = makeOff + (uint)makeBytes.Length;
        uint dateOff = modelOff + (uint)modelBytes.Length;

        // Entry 1: Make (0x010F), ASCII (2)
        bw.Write((ushort)0x010F);
        bw.Write((ushort)2);
        bw.Write((uint)makeBytes.Length);
        bw.Write(makeOff);

        // Entry 2: Model (0x0110), ASCII (2)
        bw.Write((ushort)0x0110);
        bw.Write((ushort)2);
        bw.Write((uint)modelBytes.Length);
        bw.Write(modelOff);

        // Entry 3: ModifyDate (0x0132), ASCII (2)
        bw.Write((ushort)0x0132);
        bw.Write((ushort)2);
        bw.Write((uint)dateBytes.Length);
        bw.Write(dateOff);

        // Next IFD offset = 0
        bw.Write((uint)0);

        bw.Write(makeBytes);
        bw.Write(modelBytes);
        bw.Write(dateBytes);

        return ms.ToArray();
    }

    private static byte[] CreateEmbeddedGzipStream(string content)
    {
        using var outMs = new MemoryStream();
        using (var gz = new GZipStream(outMs, CompressionLevel.Optimal, leaveOpen: true))
        {
            byte[] raw = Encoding.UTF8.GetBytes(content);
            gz.Write(raw, 0, raw.Length);
        }
        return outMs.ToArray();
    }

    private static void WriteBE32(BinaryWriter bw, uint value)
    {
        bw.Write((byte)(value >> 24));
        bw.Write((byte)(value >> 16));
        bw.Write((byte)(value >> 8));
        bw.Write((byte)value);
    }
}

