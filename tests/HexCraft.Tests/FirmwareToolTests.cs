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

        Assert.Equal(35, FirmwareToolService.DefaultRegistry.Parsers.Count);
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
    public void AllSignatureTypes_Have_Matching_Extractors_And_Unpack_Jffs2_ExtFs_Ubi_SquashFs_Bzip2_Xz_Zstd()
    {
        var sigRegistry = FirmwareToolService.DefaultRegistry;
        var extRegistry = FirmwareToolService.DefaultExtractors;

        // 1. Verify all 35 signature parsers (24 Binwalk + 11 IDArc) map to a registered IFirmwareExtractor
        Assert.Equal(35, sigRegistry.Parsers.Count);
        foreach (var parser in sigRegistry.Parsers)
        {
            Assert.Contains(extRegistry.Extractors, e => e.CanExtract(parser.Name, parser.DisplayName, ReadOnlySpan<byte>.Empty));
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "HexCraft_ExtAllTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempRoot);

        try
        {
            // 2. JFFS2 Image (DIRENT for "config.json" ino=2 under root pino=1 + zlib-compressed INODE for ino=2)
            byte[] jffsPayload = Encoding.UTF8.GetBytes("{\"device\":\"HexCraft-Router\"}");
            byte[] jffsZlib;
            using (var zMs = new MemoryStream())
            {
                using (var zl = new System.IO.Compression.ZLibStream(zMs, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
                    zl.Write(jffsPayload);
                jffsZlib = zMs.ToArray();
            }

            byte[] direntNode = new byte[52]; // 40 + "config.json" (11B) + 1 pad = 52
            BinaryPrimitives.WriteUInt16LittleEndian(direntNode.AsSpan(0, 2), 0x1985);
            BinaryPrimitives.WriteUInt16LittleEndian(direntNode.AsSpan(2, 2), 0xE001); // DIRENT
            BinaryPrimitives.WriteUInt32LittleEndian(direntNode.AsSpan(4, 4), 51);     // totlen = 40 + 11
            BinaryPrimitives.WriteUInt32LittleEndian(direntNode.AsSpan(12, 4), 1);     // pino = 1 (root)
            BinaryPrimitives.WriteUInt32LittleEndian(direntNode.AsSpan(16, 4), 1);     // version = 1
            BinaryPrimitives.WriteUInt32LittleEndian(direntNode.AsSpan(20, 4), 2);     // ino = 2
            direntNode[28] = 11; // nsize
            direntNode[29] = 8;  // DT_REG
            "config.json"u8.CopyTo(direntNode.AsSpan(40, 11));

            int inodeTotLen = 68 + jffsZlib.Length;
            byte[] inodeNode = new byte[(inodeTotLen + 3) & ~3];
            BinaryPrimitives.WriteUInt16LittleEndian(inodeNode.AsSpan(0, 2), 0x1985);
            BinaryPrimitives.WriteUInt16LittleEndian(inodeNode.AsSpan(2, 2), 0xE002); // INODE
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(4, 4), (uint)inodeTotLen);
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(12, 4), 2);    // ino = 2
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(16, 4), 1);    // version = 1
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(28, 4), (uint)jffsPayload.Length); // isize
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(44, 4), 0);    // offset = 0
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(48, 4), (uint)jffsZlib.Length);    // csize
            BinaryPrimitives.WriteUInt32LittleEndian(inodeNode.AsSpan(52, 4), (uint)jffsPayload.Length); // dsize
            inodeNode[56] = 0x06; // JFFS2_COMPR_ZLIB
            jffsZlib.AsSpan().CopyTo(inodeNode.AsSpan(68));

            byte[] jffsImg = new byte[direntNode.Length + inodeNode.Length];
            direntNode.AsSpan().CopyTo(jffsImg.AsSpan(0));
            inodeNode.AsSpan().CopyTo(jffsImg.AsSpan(direntNode.Length));

            var jffsRes = extRegistry.ExtractPayload(jffsImg, "jffs2", "JFFS2 Filesystem", Path.Combine(tempRoot, "jffs2_out"));
            Assert.True(jffsRes.Success);
            Assert.Contains(jffsRes.ExtractedFiles, f => f.EndsWith("config.json") && File.ReadAllText(f) == "{\"device\":\"HexCraft-Router\"}");

            // 3. Linux EXT4 Image (1024B blocks: Block 1=SB, Block 2=BGDT, Block 3=InodeTable, Block 4=RootDir, Block 5=FileData)
            byte[] extImg = new byte[6 * 1024];
            var sb = extImg.AsSpan(1024, 1024);
            BinaryPrimitives.WriteUInt32LittleEndian(sb.Slice(0x00, 4), 16);   // s_inodes_count
            BinaryPrimitives.WriteUInt32LittleEndian(sb.Slice(0x04, 4), 6);    // s_blocks_count
            BinaryPrimitives.WriteUInt32LittleEndian(sb.Slice(0x18, 4), 0);    // 1024B blocks
            BinaryPrimitives.WriteUInt32LittleEndian(sb.Slice(0x20, 4), 1024); // blocks_per_group
            BinaryPrimitives.WriteUInt32LittleEndian(sb.Slice(0x28, 4), 16);   // inodes_per_group
            BinaryPrimitives.WriteUInt16LittleEndian(sb.Slice(0x38, 2), 0xEF53);
            BinaryPrimitives.WriteUInt32LittleEndian(sb.Slice(0x4C, 4), 1);    // rev 1
            BinaryPrimitives.WriteUInt16LittleEndian(sb.Slice(0x58, 2), 128);  // inode_size = 128
            // Block 2 (offset 2048): BGDT -> bg_inode_table = 3
            BinaryPrimitives.WriteUInt32LittleEndian(extImg.AsSpan(2048 + 8, 4), 3);
            // Block 3 (offset 3072): Inode #2 (Root dir) is at index 1 -> offset 3072 + 128
            var rootIno = extImg.AsSpan(3072 + 128, 128);
            BinaryPrimitives.WriteUInt16LittleEndian(rootIno.Slice(0, 2), 0x41ED); // dir
            BinaryPrimitives.WriteUInt32LittleEndian(rootIno.Slice(4, 4), 1024);   // size = 1024
            BinaryPrimitives.WriteUInt32LittleEndian(rootIno.Slice(40, 4), 4);     // i_block[0] = Block 4
            // Inode #3 ("passwd" regular file) at index 2 -> offset 3072 + 256, using EXT4 Extent Tree (0xF30A)
            var fileIno = extImg.AsSpan(3072 + 256, 128);
            BinaryPrimitives.WriteUInt16LittleEndian(fileIno.Slice(0, 2), 0x81A4); // reg file
            BinaryPrimitives.WriteUInt32LittleEndian(fileIno.Slice(4, 4), 19);     // "root:x:0:0:ext4fs\n" (18B) + 1
            BinaryPrimitives.WriteUInt32LittleEndian(fileIno.Slice(32, 4), 0x80000); // EXT4_EXTENTS_FL
            BinaryPrimitives.WriteUInt16LittleEndian(fileIno.Slice(40, 2), 0xF30A);  // eh_magic
            BinaryPrimitives.WriteUInt16LittleEndian(fileIno.Slice(42, 2), 1);       // eh_entries = 1
            BinaryPrimitives.WriteUInt16LittleEndian(fileIno.Slice(46, 2), 0);       // eh_depth = 0
            BinaryPrimitives.WriteUInt16LittleEndian(fileIno.Slice(52 + 4, 2), 1);   // ee_len = 1 block
            BinaryPrimitives.WriteUInt32LittleEndian(fileIno.Slice(52 + 8, 4), 5);   // ee_start_lo = Block 5
            // Block 4 (offset 4096): Root directory entry pointing to Inode #3 ("passwd")
            var dirBlk = extImg.AsSpan(4096, 1024);
            BinaryPrimitives.WriteUInt32LittleEndian(dirBlk.Slice(0, 4), 3);    // inode = 3
            BinaryPrimitives.WriteUInt16LittleEndian(dirBlk.Slice(4, 2), 1024); // rec_len = 1024
            dirBlk[6] = 6; // name_len = 6
            dirBlk[7] = 1; // FT_REG_FILE
            "passwd"u8.CopyTo(dirBlk.Slice(8, 6));
            // Block 5 (offset 5120): File content
            "root:x:0:0:ext4fs!\n"u8.CopyTo(extImg.AsSpan(5120, 19));

            var extRes = extRegistry.ExtractPayload(extImg, "extfs", "Linux EXT2/3/4 Filesystem", Path.Combine(tempRoot, "ext_out"));
            Assert.True(extRes.Success);
            Assert.Contains(extRes.ExtractedFiles, f => f.EndsWith("passwd") && File.ReadAllText(f) == "root:x:0:0:ext4fs!\n");

            // 4. UBI Image (2 PEBs of 16KB: PEB 0 = Layout Volume Table naming vol 0 "rootfs", PEB 1 = Vol 0 LEB 0)
            byte[] ubiImg = new byte[32 * 1024];
            // PEB 0 @ 0:
            "UBI#"u8.CopyTo(ubiImg.AsSpan(0, 4));
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(16, 4), 64);  // vid_hdr @ +64
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(20, 4), 128); // data @ +128
            "UBI!"u8.CopyTo(ubiImg.AsSpan(64, 4));
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(64 + 8, 4), 0x7FFFEFFF); // Layout volume
            // Volume table record #0 @ +128: reserved_pebs=1, name_len=6, name="rootfs"
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(128, 4), 1);
            BinaryPrimitives.WriteUInt16BigEndian(ubiImg.AsSpan(128 + 21, 2), 6);
            "rootfs"u8.CopyTo(ubiImg.AsSpan(128 + 23, 6));
            // PEB 1 @ 16384:
            "UBI#"u8.CopyTo(ubiImg.AsSpan(16384, 4));
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(16384 + 16, 4), 64);
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(16384 + 20, 4), 128);
            "UBI!"u8.CopyTo(ubiImg.AsSpan(16384 + 64, 4));
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(16384 + 64 + 8, 4), 0);  // vol_id = 0
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(16384 + 64 + 12, 4), 0); // lnum = 0
            BinaryPrimitives.WriteUInt32BigEndian(ubiImg.AsSpan(16384 + 64 + 20, 4), 16); // data_size = 16
            "UBI_ROOTFS_DATA!"u8.CopyTo(ubiImg.AsSpan(16384 + 128, 16));

            var ubiRes = extRegistry.ExtractPayload(ubiImg, "ubi", "UBI Eraseblock Header", Path.Combine(tempRoot, "ubi_out"));
            Assert.True(ubiRes.Success);
            Assert.Contains(ubiRes.ExtractedFiles, f => f.EndsWith("ubi_vol0_rootfs.bin") && File.ReadAllText(f) == "UBI_ROOTFS_DATA!");

            // 5. Zstandard Raw_Block + RLE_Block Frame
            // Magic (4B) + FHD (0x20 = Single_Segment_Flag, 1B FCS = 10) + Raw_Block (last=0, type=0, size=5 -> "ZSTD_") + RLE_Block (last=1, type=1, size=5, byte='!')
            byte[] zstdFrame = new byte[]
            {
                0x28, 0xB5, 0x2F, 0xFD,
                0x20, 10,
                (byte)((5 << 3) | (0 << 1) | 0), 0x00, 0x00,
                (byte)'Z', (byte)'S', (byte)'T', (byte)'D', (byte)'_',
                (byte)((5 << 3) | (1 << 1) | 1), 0x00, 0x00,
                (byte)'!'
            };
            var zstdRes = extRegistry.ExtractPayload(zstdFrame, "zstd", "Zstandard (Zstd) Stream", Path.Combine(tempRoot, "zstd_out"));
            Assert.True(zstdRes.Success);
            Assert.Equal("ZSTD_!!!!!", File.ReadAllText(zstdRes.ExtractedFiles[0]));

            // 6. XZ Container with Uncompressed LZMA2 Chunk
            byte[] xzFrame = new byte[]
            {
                0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, // Magic
                0x00, 0x00,                         // Flags (CheckType = 0 None)
                0x00, 0x00, 0x00, 0x00,             // CRC32
                0x01, 0x00, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, // 8-byte Block Header (size = (1+1)*4 = 8)
                0x01, 0x00, 0x06,                   // LZMA2 uncompressed chunk of length 6+1 = 7 bytes
                (byte)'X', (byte)'Z', (byte)'_', (byte)'T', (byte)'E', (byte)'S', (byte)'T',
                0x00, 0x00,                         // End of LZMA2 + padding
                0x00                                // Index indicator
            };
            var xzRes = extRegistry.ExtractPayload(xzFrame, "xz", "XZ Compressed Stream", Path.Combine(tempRoot, "xz_out"));
            Assert.True(xzRes.Success);
            Assert.Equal("XZ_TEST", File.ReadAllText(xzRes.ExtractedFiles[0]));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
                Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Fact]
    public void IdArcSignatures_And_CarvingExtractors_Detect_And_Unpack_Cab_Rar_Arj_Lzh_Arc_Szdd_And_MzSfxOverlay()
    {
        var sigRegistry = FirmwareToolService.DefaultRegistry;
        var extRegistry = FirmwareToolService.DefaultExtractors;
        string tempRoot = Path.Combine(Path.GetTempPath(), "HexCraft_IdArcTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempRoot);

        try
        {
            // 1. Microsoft Cabinet (CAB — IDArc #79) with MSZIP ("CK" + Deflate) compressed file "driver.inf"
            byte[] cabFileText = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$Windows NT$\"\n");
            byte[] mszipBlock;
            using (var ms = new MemoryStream())
            {
                ms.Write("CK"u8);
                using (var def = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
                    def.Write(cabFileText);
                mszipBlock = ms.ToArray();
            }

            // Layout: [0..36] CFHEADER, [36..44] CFFOLDER, [44..71] CFFILE (16B + "driver.inf\0" = 27B), [71..79+mszipBlock.Length] CFDATA
            int cfDataStart = 44 + 27;
            int totalCabLen = cfDataStart + 8 + mszipBlock.Length;
            byte[] cabImg = new byte[totalCabLen];
            "MSCF\0\0\0\0"u8.CopyTo(cabImg.AsSpan(0, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(cabImg.AsSpan(8, 4), (uint)totalCabLen); // cbCabinet
            BinaryPrimitives.WriteUInt32LittleEndian(cabImg.AsSpan(16, 4), 44);               // coffFiles
            cabImg[24] = 3; cabImg[25] = 1;                                                   // v1.3
            BinaryPrimitives.WriteUInt16LittleEndian(cabImg.AsSpan(26, 2), 1);                // cFolders = 1
            BinaryPrimitives.WriteUInt16LittleEndian(cabImg.AsSpan(28, 2), 1);                // cFiles = 1
            // CFFOLDER @ +36: coffCabStart=cfDataStart, cCFData=1, typeCompress=1 (MSZIP)
            BinaryPrimitives.WriteUInt32LittleEndian(cabImg.AsSpan(36, 4), (uint)cfDataStart);
            BinaryPrimitives.WriteUInt16LittleEndian(cabImg.AsSpan(40, 2), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(cabImg.AsSpan(42, 2), 1);
            // CFFILE @ +44: cbFile, uoffFolderStart=0, iFolder=0, name="driver.inf\0"
            BinaryPrimitives.WriteUInt32LittleEndian(cabImg.AsSpan(44, 4), (uint)cabFileText.Length);
            "driver.inf\0"u8.CopyTo(cabImg.AsSpan(60, 11));
            // CFDATA @ cfDataStart: csum=0, cbData=mszipBlock.Length, cbUncomp=cabFileText.Length
            BinaryPrimitives.WriteUInt16LittleEndian(cabImg.AsSpan(cfDataStart + 4, 2), (ushort)mszipBlock.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(cabImg.AsSpan(cfDataStart + 6, 2), (ushort)cabFileText.Length);
            mszipBlock.AsSpan().CopyTo(cabImg.AsSpan(cfDataStart + 8));

            var cabHits = sigRegistry.Scan(cabImg);
            Assert.Contains(cabHits, h => h.SignatureType == "Microsoft Cabinet (CAB)" && h.EstimatedSize == totalCabLen);
            var cabRes = extRegistry.ExtractPayload(cabImg, "cab", "Microsoft Cabinet (CAB)", Path.Combine(tempRoot, "cab_out"));
            Assert.True(cabRes.Success);
            Assert.Contains(cabRes.ExtractedFiles, f => f.EndsWith("driver.inf") && File.ReadAllText(f) == "[Version]\nSignature=\"$Windows NT$\"\n");

            // 2. RAR v4.x Archive (IDArc #15) with Multi-Volume + AV-Protected flags and Stored file "readme.txt"
            byte[] rarPayload = "IDArc RAR Stored File!"u8.ToArray();
            // [0..7] Marker, [7..20] ARCHIVE_HEAD (type=0x73, flags=0x0021 Volume+AV, size=13), [20..62] FILE_HEAD (type=0x74, size=42, method=0x30, name="readme.txt"), [62..84] payload, [84..91] ENDARC (0x7B, size=7)
            byte[] rarImg = new byte[91];
            new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }.AsSpan().CopyTo(rarImg.AsSpan(0, 7));
            rarImg[7 + 2] = 0x73; // ARCHIVE_HEAD
            BinaryPrimitives.WriteUInt16LittleEndian(rarImg.AsSpan(7 + 3, 2), 0x0021); // MHD_VOLUME | MHD_AV
            BinaryPrimitives.WriteUInt16LittleEndian(rarImg.AsSpan(7 + 5, 2), 13);
            rarImg[20 + 2] = 0x74; // FILE_HEAD
            BinaryPrimitives.WriteUInt16LittleEndian(rarImg.AsSpan(20 + 3, 2), 0x8000);
            BinaryPrimitives.WriteUInt16LittleEndian(rarImg.AsSpan(20 + 5, 2), 42); // 32 + 10 ("readme.txt")
            BinaryPrimitives.WriteUInt32LittleEndian(rarImg.AsSpan(20 + 7, 4), (uint)rarPayload.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(rarImg.AsSpan(20 + 11, 4), (uint)rarPayload.Length);
            rarImg[20 + 25] = 0x30; // Storing
            BinaryPrimitives.WriteUInt16LittleEndian(rarImg.AsSpan(20 + 26, 2), 10); // nameSize = 10
            "readme.txt"u8.CopyTo(rarImg.AsSpan(20 + 32, 10));
            rarPayload.AsSpan().CopyTo(rarImg.AsSpan(62, rarPayload.Length));
            rarImg[84 + 2] = 0x7B; // ENDARC_HEAD
            BinaryPrimitives.WriteUInt16LittleEndian(rarImg.AsSpan(84 + 5, 2), 7);

            var rarHits = sigRegistry.Scan(rarImg);
            Assert.Contains(rarHits, h => h.SignatureType == "RAR Archive" && h.Description.Contains("multi-volume") && h.Description.Contains("AV-protected") && h.EstimatedSize == 91);
            var rarRes = extRegistry.ExtractPayload(rarImg, "rar", "RAR Archive", Path.Combine(tempRoot, "rar_out"));
            Assert.True(rarRes.Success);
            Assert.Contains(rarRes.ExtractedFiles, f => f.EndsWith("readme.txt") && File.ReadAllText(f) == "IDArc RAR Stored File!");

            // 3. SEA ARC Archive (IDArc #1 `ArcMethod`) with RLE90 (method=3) compressed file "BANNER.TXT"
            // RLE90 stream: 'A', 0x90, 8 (repeats 'A' 8 times total) + 'B', 0x90, 4 (repeats 'B' 4 times total) -> "AAAAAAAABBBB" (12B)
            byte[] arcRle = new byte[] { (byte)'A', 0x90, 8, (byte)'B', 0x90, 4 };
            byte[] arcImg = new byte[29 + arcRle.Length + 2];
            arcImg[0] = 0x1A;
            arcImg[1] = 0x03; // Method 3 = RLE90
            "BANNER.TXT\0"u8.CopyTo(arcImg.AsSpan(2, 11));
            BinaryPrimitives.WriteUInt32LittleEndian(arcImg.AsSpan(15, 4), (uint)arcRle.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(arcImg.AsSpan(25, 4), 12); // origSize = 12
            arcRle.AsSpan().CopyTo(arcImg.AsSpan(29));
            arcImg[29 + arcRle.Length] = 0x1A;
            arcImg[29 + arcRle.Length + 1] = 0x00; // EOF marker

            var arcHits = sigRegistry.Scan(arcImg);
            Assert.Contains(arcHits, h => h.SignatureType == "SEA ARC / PAK Archive" && h.EstimatedSize == arcImg.Length);
            var arcRes = extRegistry.ExtractPayload(arcImg, "arc", "SEA ARC / PAK Archive", Path.Combine(tempRoot, "arc_out"));
            Assert.True(arcRes.Success);
            Assert.Contains(arcRes.ExtractedFiles, f => f.EndsWith("BANNER.TXT") && File.ReadAllText(f) == "AAAAAAAABBBB");

            // 4. MS Compress SZDD (IDArc #84) LZSS stream
            // Header (14B) + Control byte 0x0F (4 literals "SZDD" + 1 match from initial 0x20 space ring buffer of len 4 -> "SZDD    ")
            byte[] szddImg = new byte[14 + 1 + 4 + 2];
            new byte[] { 0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33, (byte)'A', (byte)'e' }.AsSpan().CopyTo(szddImg.AsSpan(0, 10));
            BinaryPrimitives.WriteUInt32LittleEndian(szddImg.AsSpan(10, 4), 8); // uncompSize = 8 ("SZDD    ")
            szddImg[14] = 0x0F; // bits 0..3 = 1 (literal), bit 4 = 0 (match)
            "SZDD"u8.CopyTo(szddImg.AsSpan(15, 4));
            szddImg[19] = 0x00; // match offset 0 (contains 0x20 spaces)
            szddImg[20] = 0x01; // match len = 1 + 3 = 4 spaces

            var szddHits = sigRegistry.Scan(szddImg);
            Assert.Contains(szddHits, h => h.SignatureType == "MS Compress (SZDD/KWAJ)");
            var szddRes = extRegistry.ExtractPayload(szddImg, "mscompress", "MS Compress (SZDD/KWAJ)", Path.Combine(tempRoot, "szdd_out"));
            Assert.True(szddRes.Success);
            Assert.Equal("SZDD    ", File.ReadAllText(szddRes.ExtractedFiles[0]));

            // 5. MZ Self-Extracting Archive (SFX Overlay — ported from idarc/exe.go)
            // 512-byte MZ stub (lastPageSize = 512, pages = 1 -> stubSize = 512) + appended SEA ARC archive!
            byte[] sfxImg = new byte[512 + arcImg.Length];
            "MZ"u8.CopyTo(sfxImg.AsSpan(0, 2));
            BinaryPrimitives.WriteUInt16LittleEndian(sfxImg.AsSpan(2, 2), 512); // lastPageSize
            BinaryPrimitives.WriteUInt16LittleEndian(sfxImg.AsSpan(4, 2), 1);   // pages = 1
            arcImg.AsSpan().CopyTo(sfxImg.AsSpan(512));

            var sfxHits = sigRegistry.Scan(sfxImg);
            Assert.Contains(sfxHits, h => h.SignatureType == "MZ Self-Extracting Archive (SFX)" && h.Description.Contains("SEA ARC / PAK Archive"));
            var sfxRes = extRegistry.ExtractPayload(
                sfxImg,
                "sfx_overlay",
                "MZ Self-Extracting Archive (SFX)",
                Path.Combine(tempRoot, "sfx_out"),
                recursiveScanner: sigRegistry,
                maxRecursionDepth: 2);
            Assert.True(sfxRes.Success);
            // Verify both the carved SFX stub AND the recursively unpacked BANNER.TXT from the appended ARC overlay!
            Assert.Contains(sfxRes.ExtractedFiles, f => f.EndsWith("sfx_exe_stub.exe"));
            Assert.Contains(sfxRes.ExtractedFiles, f => f.EndsWith("BANNER.TXT") && File.ReadAllText(f) == "AAAAAAAABBBB");
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
