using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Text;
using HexCraft.Core.Analysis;
using HexCraft.Core.Buffers;
using HexCraft.Tools;
using HexCraft.Tools.Signatures;
using Xunit;

namespace HexCraft.Tests;

public class FirmwareToolTests
{
    [Fact]
    public void BuiltinSignatureScanner_Detects_Png_SquashFs_And_Gzip_In_Firmware_Blob()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "firmware_test.bin");

        var entries = FirmwareToolService.ScanSignatures(doc);

        Assert.Contains(entries, e => e.SignatureType == "PNG Image" && e.Offset == 0);
        Assert.Contains(entries, e => e.SignatureType == "SquashFS Filesystem" && e.Offset == 0x1E0 && e.CanUnsquashfs);
        Assert.Contains(entries, e => e.SignatureType == "GZip Stream" && e.Offset == 0x260);
    }

    [Fact]
    public void ExtensibleSignatureRegistry_Detects_Top10_Binwalk_Firmware_Signatures_And_Rejects_FalsePositives()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        // 1. U-Boot uImage at 0x00 (64 bytes header)
        byte[] uimage = new byte[64];
        uimage[0] = 0x27; uimage[1] = 0x05; uimage[2] = 0x19; uimage[3] = 0x56;
        BinaryPrimitives.WriteUInt32BigEndian(uimage.AsSpan(12, 4), 4096); // data size
        uimage[28] = 5;  // Linux
        uimage[29] = 22; // ARM64
        uimage[30] = 2;  // Kernel
        uimage[31] = 1;  // GZip
        Encoding.ASCII.GetBytes("Linux-6.6-Router").CopyTo(uimage.AsSpan(32));
        bw.Write(uimage);

        // 2. False-Positive SquashFS magic ("hsqs" with invalid block_log = 3) — MUST BE REJECTED
        bw.Write("hsqs"u8);
        bw.Write(new byte[60]);

        // 3. Flattened Device Tree (DTB) at 0x80
        byte[] dtb = new byte[48];
        dtb[0] = 0xD0; dtb[1] = 0x0D; dtb[2] = 0xFE; dtb[3] = 0xED;
        BinaryPrimitives.WriteUInt32BigEndian(dtb.AsSpan(4, 4), 2048); // totalsize
        BinaryPrimitives.WriteUInt32BigEndian(dtb.AsSpan(8, 4), 56);   // off_dt_struct
        BinaryPrimitives.WriteUInt32BigEndian(dtb.AsSpan(12, 4), 512); // off_dt_strings
        BinaryPrimitives.WriteUInt32BigEndian(dtb.AsSpan(16, 4), 40);  // off_mem_rsvmap
        BinaryPrimitives.WriteUInt32BigEndian(dtb.AsSpan(20, 4), 17);  // version 17
        BinaryPrimitives.WriteUInt32BigEndian(dtb.AsSpan(24, 4), 16);  // last_comp_version 16
        bw.Write(dtb);

        // 4. XZ Stream at 0xB0 (with CRC64 flag 0x04 and "YZ" footer)
        bw.Write(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, (byte)'Y', (byte)'Z' });

        // 5. LZMA Stream at 0xBE (props 0x5D, 8 MB dictionary = 0x00800000, decompSize = 65536)
        byte[] lzma = new byte[16];
        lzma[0] = 0x5D;
        BinaryPrimitives.WriteUInt32LittleEndian(lzma.AsSpan(1, 4), 8388608u);
        BinaryPrimitives.WriteUInt64LittleEndian(lzma.AsSpan(5, 8), 65536UL);
        bw.Write(lzma);

        // 6. UBI Erase Count Header ("UBI#")
        byte[] ubi = new byte[64];
        "UBI#"u8.CopyTo(ubi);
        ubi[4] = 1; // version 1
        BinaryPrimitives.WriteUInt32BigEndian(ubi.AsSpan(16, 4), 0x800);  // VID header offset
        BinaryPrimitives.WriteUInt32BigEndian(ubi.AsSpan(20, 4), 0x1000); // data offset
        bw.Write(ubi);

        // 7. JFFS2 Inode Node (LE 0x1985, nodeType 0xE002, len 68)
        byte[] jffs2 = new byte[16];
        jffs2[0] = 0x85; jffs2[1] = 0x19;
        BinaryPrimitives.WriteUInt16LittleEndian(jffs2.AsSpan(2, 2), 0xE002);
        BinaryPrimitives.WriteUInt32LittleEndian(jffs2.AsSpan(4, 4), 68);
        bw.Write(jffs2);

        // 8. CPIO SVR4 ASCII header ("070701" + 104 hex chars + filename "init\0")
        string cpioHeader = "070701"
            + "00000001" // ino
            + "000081ED" // mode
            + "00000000" // uid
            + "00000000" // gid
            + "00000001" // nlink
            + "65432100" // mtime
            + "00000010" // filesize = 16
            + "00000000" + "00000000" + "00000000" + "00000000"
            + "00000005" // namesize = 5 ("init\0")
            + "00000000";
        bw.Write(Encoding.ASCII.GetBytes(cpioHeader));
        bw.Write("init\0"u8);

        // 9. CramFS Superblock (LE 0x28CD3D45 + "Compressed ROMFS" at +16)
        byte[] cramfs = new byte[64];
        cramfs[0] = 0x45; cramfs[1] = 0x3D; cramfs[2] = 0xCD; cramfs[3] = 0x28;
        BinaryPrimitives.WriteUInt32LittleEndian(cramfs.AsSpan(4, 4), 131072);
        "Compressed ROMFS"u8.CopyTo(cramfs.AsSpan(16, 16));
        "OpenWrt-Root"u8.CopyTo(cramfs.AsSpan(48, 12));
        bw.Write(cramfs);

        using var doc = new BinaryDocument(ms.ToArray(), "multi_sig.bin");
        var matches = FirmwareToolService.ScanSignatures(doc);

        Assert.Contains(matches, m => m.SignatureType == "U-Boot uImage" && m.Description.Contains("Linux-6.6-Router"));
        Assert.DoesNotContain(matches, m => m.SignatureType == "SquashFS Filesystem"); // False-positive rejected!
        Assert.Contains(matches, m => m.SignatureType == "Flattened Device Tree (DTB)" && m.Description.Contains("total size: 2048 bytes"));
        Assert.Contains(matches, m => m.SignatureType == "XZ Stream" && m.Description.Contains("CRC64"));
        Assert.Contains(matches, m => m.SignatureType == "LZMA Stream" && m.Description.Contains("8388608"));
        Assert.Contains(matches, m => m.SignatureType == "UBI / UBIFS Image" && m.Description.Contains("VID header offset: 0x800"));
        Assert.Contains(matches, m => m.SignatureType == "JFFS2 Filesystem" && m.Description.Contains("0xE002"));
        Assert.Contains(matches, m => m.SignatureType == "CPIO Archive" && m.Description.Contains("\"init\""));
        Assert.Contains(matches, m => m.SignatureType == "CramFS Filesystem" && m.Description.Contains("\"OpenWrt-Root\""));
    }

    [Fact]
    public void ExtendedSignatureRegistry_Detects_Trx_Seama_Tar_7z_Bzip2_Zstd_Pem_OpenSsl_ExtFs_And_RomFs()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);

        // 1. Broadcom TRX Header ("HDR0", len=4096, crc=0x12345678, flags=0, version=1, offsets=[28, 512, 1024])
        byte[] trx = new byte[28];
        "HDR0"u8.CopyTo(trx);
        BinaryPrimitives.WriteUInt32LittleEndian(trx.AsSpan(4, 4), 4096);
        BinaryPrimitives.WriteUInt32LittleEndian(trx.AsSpan(8, 4), 0x12345678);
        BinaryPrimitives.WriteUInt16LittleEndian(trx.AsSpan(14, 2), 1); // version 1
        BinaryPrimitives.WriteUInt32LittleEndian(trx.AsSpan(16, 4), 28);
        BinaryPrimitives.WriteUInt32LittleEndian(trx.AsSpan(20, 4), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(trx.AsSpan(24, 4), 1024);
        bw.Write(trx);

        // 2. SEAMA Header (0x5EA3A417, reserved=0, metaSize=16, imageSize=2048, 16-byte MD5)
        byte[] seama = new byte[44];
        seama[0] = 0x5E; seama[1] = 0xA3; seama[2] = 0xA4; seama[3] = 0x17;
        BinaryPrimitives.WriteUInt16BigEndian(seama.AsSpan(4, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(seama.AsSpan(6, 2), 16);
        BinaryPrimitives.WriteUInt32BigEndian(seama.AsSpan(8, 4), 2048);
        bw.Write(seama);

        // 3. POSIX ustar TAR block (512 bytes header + 512 bytes payload)
        byte[] tarBlock = new byte[512];
        Encoding.ASCII.GetBytes("etc/passwd").CopyTo(tarBlock.AsSpan(0));
        Encoding.ASCII.GetBytes("0000644\0").CopyTo(tarBlock.AsSpan(100));
        Encoding.ASCII.GetBytes("00000000020\0").CopyTo(tarBlock.AsSpan(124)); // 16 bytes (020 octal)
        tarBlock[156] = (byte)'0';
        "ustar\0"u8.CopyTo(tarBlock.AsSpan(257));
        "00"u8.CopyTo(tarBlock.AsSpan(263));
        // Compute TAR checksum
        int sum = 0;
        for (int i = 0; i < 512; i++)
            sum += (i >= 148 && i < 156) ? (byte)' ' : tarBlock[i];
        string octalChk = Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ";
        Encoding.ASCII.GetBytes(octalChk).CopyTo(tarBlock.AsSpan(148, 8));
        bw.Write(tarBlock);
        byte[] tarPayload = new byte[512];
        Encoding.ASCII.GetBytes("root:x:0:0:root\n").CopyTo(tarPayload, 0);
        bw.Write(tarPayload);

        // 4. 7-Zip Archive Header (32 bytes)
        byte[] sevenZip = new byte[32];
        new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04 }.AsSpan().CopyTo(sevenZip.AsSpan(0));
        BinaryPrimitives.WriteUInt32LittleEndian(sevenZip.AsSpan(8, 4), 0xAABBCCDD); // CRC
        BinaryPrimitives.WriteUInt64LittleEndian(sevenZip.AsSpan(12, 8), 1024);      // nextHeaderOffset
        BinaryPrimitives.WriteUInt64LittleEndian(sevenZip.AsSpan(20, 8), 128);       // nextHeaderSize
        bw.Write(sevenZip);

        // 5. BZip2 Stream ("BZh9" + pi magic 0x314159265359)
        bw.Write(new byte[] { (byte)'B', (byte)'Z', (byte)'h', (byte)'9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x00, 0x00 });

        // 6. Zstandard Stream (0x28 0xB5 0x2F 0xFD + FHD 0x24 = singleSegment + checksum)
        bw.Write(new byte[] { 0x28, 0xB5, 0x2F, 0xFD, 0x24, 0x40, 0x00, 0x00 });

        // 7. PEM Certificate block
        bw.Write("-----BEGIN CERTIFICATE-----\nMIIB+TCCAWACCQDX\n-----END CERTIFICATE-----\n"u8);

        // 8. OpenSSL Salted__ stream
        bw.Write("Salted__"u8);
        bw.Write(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });

        // 9. Linux EXT4 Superblock (256 bytes, magic 0xEF53 at +0x38)
        byte[] extSb = new byte[256];
        BinaryPrimitives.WriteUInt32LittleEndian(extSb.AsSpan(0, 4), 2048);   // inodes_count
        BinaryPrimitives.WriteUInt32LittleEndian(extSb.AsSpan(4, 4), 8192);   // blocks_count
        BinaryPrimitives.WriteUInt32LittleEndian(extSb.AsSpan(12, 4), 4000);  // free_blocks
        BinaryPrimitives.WriteUInt32LittleEndian(extSb.AsSpan(16, 4), 1800);  // free_inodes
        BinaryPrimitives.WriteUInt32LittleEndian(extSb.AsSpan(24, 4), 2);     // log_block_size = 2 (4096 B)
        extSb[0x38] = 0x53; extSb[0x39] = 0xEF;                               // EXT_SUPER_MAGIC
        BinaryPrimitives.WriteUInt16LittleEndian(extSb.AsSpan(58, 2), 1);     // state = clean
        BinaryPrimitives.WriteUInt32LittleEndian(extSb.AsSpan(76, 4), 1);     // rev_level = 1
        "rootfs_ext4\0"u8.CopyTo(extSb.AsSpan(120));
        bw.Write(extSb);

        // 10. ROMFS v1 ("-rom1fs-" + size BE 4096 + crc BE + "romfs_vol\0")
        byte[] romfs = new byte[32];
        "-rom1fs-"u8.CopyTo(romfs);
        BinaryPrimitives.WriteUInt32BigEndian(romfs.AsSpan(8, 4), 4096);
        BinaryPrimitives.WriteUInt32BigEndian(romfs.AsSpan(12, 4), 0xCAFEBABE);
        "romfs_vol\0"u8.CopyTo(romfs.AsSpan(16));
        bw.Write(romfs);

        using var doc = new BinaryDocument(ms.ToArray(), "extended_sigs.bin");
        var matches = FirmwareToolService.ScanSignatures(doc);

        Assert.Equal(24, FirmwareToolService.DefaultRegistry.Parsers.Count);
        Assert.Contains(matches, m => m.SignatureType == "Broadcom TRX Firmware");
        Assert.Contains(matches, m => m.SignatureType == "SEAMA Firmware Header");
        Assert.Contains(matches, m => m.SignatureType == "POSIX TAR Archive" && m.Description.Contains("etc/passwd"));
        Assert.Contains(matches, m => m.SignatureType == "7-Zip Archive" && m.Description.Contains("version 0.4"));
        Assert.Contains(matches, m => m.SignatureType == "BZip2 Stream" && m.Description.Contains("900k"));
        Assert.Contains(matches, m => m.SignatureType == "Zstandard (Zstd) Stream");
        Assert.Contains(matches, m => m.SignatureType == "PEM Certificate / Key" && m.Description.Contains("BEGIN CERTIFICATE"));
        Assert.Contains(matches, m => m.SignatureType == "OpenSSL Encrypted Data");
        Assert.Contains(matches, m => m.SignatureType == "Linux EXT2/3/4 Filesystem" && m.Description.Contains("rootfs_ext4"));
        Assert.Contains(matches, m => m.SignatureType == "ROMFS v1 Filesystem" && m.Description.Contains("romfs_vol"));
    }

    [Fact]
    public void CarveAndExtract_Decompresses_Embedded_Gzip_Stream_Automatically()
    {
        byte[] sample = SampleBinaryFactory.CreateDemoFirmwareBlob();
        using var doc = new BinaryDocument(sample, "firmware_test.bin");

        var entries = FirmwareToolService.ScanSignatures(doc);
        var gzipEntry = entries.First(e => e.SignatureType == "GZip Stream");

        var outcome = FirmwareToolService.CarveAndExtractAsync(doc, gzipEntry).GetAwaiter().GetResult();

        Assert.True(outcome.Success);
        var decompFile = outcome.ExtractedFiles.FirstOrDefault(f => f.Contains("decompressed_"));
        Assert.NotNull(decompFile);

        string decompText = File.ReadAllText(decompFile!);
        Assert.Contains("HexCraft Embedded Initramfs Script", decompText);
    }

    [Fact]
    public void Top5FirmwareExtractors_Unpack_CramFs_RomFs_Dtb_UImage_And_Trx_In_Memory()
    {
        var registry = HexCraft.Tools.Extractors.FirmwareExtractorRegistry.CreateDefault();
        string tempRoot = Path.Combine(Path.GetTempPath(), "HexCraft_ExtractorTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempRoot);

        try
        {
            // 1. CramFS (LE) with zlib-compressed file "hello.txt" ("Hello from CramFS!")
            byte[] cramFileContent = Encoding.UTF8.GetBytes("Hello from CramFS!");
            byte[] zlibCompressed;
            using (var zMs = new MemoryStream())
            {
                using (var zl = new System.IO.Compression.ZLibStream(zMs, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
                    zl.Write(cramFileContent);
                zlibCompressed = zMs.ToArray();
            }

            // Layout: [0..64] superblock (root inode @ 32 -> dir @ offset 64, size 20)
            // [64..84] child inode (12B) + "hello.txt\0\0\0" (8B -> 3 words = 12B) = 24B
            // [88..92] 1 block pointer (u32 LE = 92 + zlibCompressed.Length)
            // [92..] zlibCompressed bytes
            byte[] cramImg = new byte[92 + zlibCompressed.Length];
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(0, 4), 0x28CD3D45);
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(4, 4), (uint)cramImg.Length);
            "Compressed ROMFS"u8.CopyTo(cramImg.AsSpan(16, 16));
            // Root inode @ +32: mode=0x41ED (dir), size=24, offset=64/4=16 -> namelen_offset = (16 << 6)
            BinaryPrimitives.WriteUInt16LittleEndian(cramImg.AsSpan(32, 2), 0x41ED);
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(36, 4), 24);
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(40, 4), 16u << 6);
            // Child inode @ +64: mode=0x81A4 (regular file), size=cramFileContent.Length, namelen=3 words (12B), offset=88/4=22
            BinaryPrimitives.WriteUInt16LittleEndian(cramImg.AsSpan(64, 2), 0x81A4);
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(68, 4), (uint)cramFileContent.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(72, 4), (22u << 6) | 3u);
            "hello.txt\0\0\0"u8.CopyTo(cramImg.AsSpan(76, 12));
            // Block pointer table @ +88: end offset = 92 + zlibCompressed.Length
            BinaryPrimitives.WriteUInt32LittleEndian(cramImg.AsSpan(88, 4), (uint)(92 + zlibCompressed.Length));
            zlibCompressed.AsSpan().CopyTo(cramImg.AsSpan(92));

            var cramRes = registry.ExtractPayload(cramImg, "cramfs", "CramFS Filesystem", Path.Combine(tempRoot, "cram_out"));
            Assert.True(cramRes.Success);
            Assert.Contains(cramRes.ExtractedFiles, f => f.EndsWith("hello.txt") && File.ReadAllText(f) == "Hello from CramFS!");

            // 2. Linux ROMFS ("-rom1fs-") with regular file "init.sh" ("#!/bin/sh\necho ok\n")
            byte[] romImg = new byte[128];
            "-rom1fs-"u8.CopyTo(romImg.AsSpan(0, 8));
            BinaryPrimitives.WriteUInt32BigEndian(romImg.AsSpan(8, 4), 128);
            "romvol\0"u8.CopyTo(romImg.AsSpan(16)); // padded to 32
            // File header @ +32: next=0 | type=2 (regular file), spec=0, size=18, checksum=0, name="init.sh\0" (padded to 16B -> data @ +64)
            BinaryPrimitives.WriteUInt32BigEndian(romImg.AsSpan(32, 4), 2u);
            BinaryPrimitives.WriteUInt32BigEndian(romImg.AsSpan(40, 4), 18u);
            "init.sh\0"u8.CopyTo(romImg.AsSpan(48));
            "#!/bin/sh\necho ok\n"u8.CopyTo(romImg.AsSpan(64));

            var romRes = registry.ExtractPayload(romImg, "romfs", "ROMFS v1 Filesystem", Path.Combine(tempRoot, "rom_out"));
            Assert.True(romRes.Success);
            Assert.Contains(romRes.ExtractedFiles, f => f.EndsWith("init.sh") && File.ReadAllText(f) == "#!/bin/sh\necho ok\n");

            // 3. Flattened Device Tree (.dtb -> .dts decompiler)
            byte[] dtbImg = new byte[128];
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(0, 4), 0xD00DFEED);
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(4, 4), 128);  // totalsize
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(8, 4), 48);   // off_dt_struct
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(12, 4), 96);  // off_dt_strings
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(16, 4), 40);  // off_mem_rsvmap
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(20, 4), 17);  // version 17
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(24, 4), 16);  // last_comp_version
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(32, 4), 16);  // size_dt_strings
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(36, 4), 48);  // size_dt_struct
            // Structure @ +48:
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(48, 4), 1);   // FDT_BEGIN_NODE ""
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(52, 4), 0);   // "" + align4
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(56, 4), 3);   // FDT_PROP
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(60, 4), 16);  // len = 16 ("HexCraft Router\0")
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(64, 4), 0);   // nameoff = 0 ("model")
            "HexCraft Router\0"u8.CopyTo(dtbImg.AsSpan(68, 16));
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(84, 4), 2);   // FDT_END_NODE
            BinaryPrimitives.WriteUInt32BigEndian(dtbImg.AsSpan(88, 4), 9);   // FDT_END
            "model\0"u8.CopyTo(dtbImg.AsSpan(96));

            var dtbRes = registry.ExtractPayload(dtbImg, "dtb", "Flattened Device Tree (DTB)", Path.Combine(tempRoot, "dtb_out"));
            Assert.True(dtbRes.Success);
            string dtsText = File.ReadAllText(dtbRes.ExtractedFiles[0]);
            Assert.Contains("/dts-v1/;", dtsText);
            Assert.Contains("model = \"HexCraft Router\";", dtsText);

            // 4. U-Boot uImage wrapping a GZip stream
            byte[] gzPayload;
            using (var ms = new MemoryStream())
            {
                using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
                    gz.Write("U-Boot Decompressed Kernel Image"u8);
                gzPayload = ms.ToArray();
            }
            byte[] uimg = new byte[64 + gzPayload.Length];
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(0, 4), 0x27051956);
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(8, 4), 1700000000);
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(12, 4), (uint)gzPayload.Length);
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(16, 4), 0x80008000);
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(20, 4), 0x80008000);
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(24, 4), HexCraft.Tools.Extractors.UImageExtractor.ComputeCrc32(gzPayload));
            uimg[28] = 5; // Linux
            uimg[29] = 2; // ARM
            uimg[30] = 2; // Kernel
            uimg[31] = 1; // GZip
            "Linux-6.6-ARM"u8.CopyTo(uimg.AsSpan(32));
            uint hdrCrc = HexCraft.Tools.Extractors.UImageExtractor.ComputeCrc32(uimg.AsSpan(0, 64));
            BinaryPrimitives.WriteUInt32BigEndian(uimg.AsSpan(4, 4), hdrCrc);
            gzPayload.AsSpan().CopyTo(uimg.AsSpan(64));

            var uimgRes = registry.ExtractPayload(uimg, "uimage", "U-Boot uImage Header", Path.Combine(tempRoot, "uimg_out"));
            Assert.True(uimgRes.Success);
            Assert.Contains(uimgRes.ExtractedFiles, f => f.EndsWith("uimage_decompressed.bin") && File.ReadAllText(f) == "U-Boot Decompressed Kernel Image");

            // 5. Broadcom TRX container with Matryoshka nested ROMFS partition
            byte[] trxImg = new byte[32 + romImg.Length];
            "HDR0"u8.CopyTo(trxImg.AsSpan(0, 4));
            BinaryPrimitives.WriteUInt32LittleEndian(trxImg.AsSpan(4, 4), (uint)trxImg.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(trxImg.AsSpan(12, 4), 1u << 16); // v1
            BinaryPrimitives.WriteUInt32LittleEndian(trxImg.AsSpan(16, 4), 32u);      // Partition 0 @ +32 (romImg)
            romImg.AsSpan().CopyTo(trxImg.AsSpan(32));

            var trxRes = registry.ExtractPayload(
                trxImg,
                "trx",
                "Broadcom TRX Firmware Header",
                Path.Combine(tempRoot, "trx_out"),
                recursiveScanner: FirmwareToolService.DefaultRegistry,
                maxRecursionDepth: 2);
            Assert.True(trxRes.Success);
            // Verify both the TRX partition AND the Matryoshka-unpacked ROMFS init.sh were extracted!
            Assert.Contains(trxRes.ExtractedFiles, f => f.EndsWith("trx_partition_0.bin"));
            Assert.Contains(trxRes.ExtractedFiles, f => f.EndsWith("init.sh"));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
                Directory.Delete(tempRoot, recursive: true);
        }
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
