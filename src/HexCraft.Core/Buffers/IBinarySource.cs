using System;
using System.IO;
using System.IO.MemoryMappedFiles;

namespace HexCraft.Core.Buffers;

/// <summary>
/// Provides memory-safe, random-access read capability over an underlying byte source.
/// </summary>
public interface IBinarySource : IDisposable
{
    long Length { get; }
    int Read(long offset, Span<byte> destination);
    byte ReadByte(long offset);
}

/// <summary>
/// In-memory byte array source.
/// </summary>
public sealed class MemoryBinarySource : IBinarySource
{
    private readonly byte[] _data;

    public MemoryBinarySource(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    public long Length => _data.LongLength;

    public int Read(long offset, Span<byte> destination)
    {
        if (offset < 0 || offset >= _data.LongLength || destination.IsEmpty)
            return 0;

        int available = (int)Math.Min(destination.Length, _data.LongLength - offset);
        _data.AsSpan((int)offset, available).CopyTo(destination);
        return available;
    }

    public byte ReadByte(long offset)
    {
        if (offset < 0 || offset >= _data.LongLength)
            throw new ArgumentOutOfRangeException(nameof(offset));
        return _data[offset];
    }

    public void Dispose()
    {
    }
}

/// <summary>
/// Memory-mapped file binary source for zero-copy, instant opening of large files on Windows 11 & Linux.
/// Falls back cleanly to a shared FileStream for small or empty files.
/// </summary>
public sealed class MemoryMappedBinarySource : IBinarySource
{
    private readonly FileStream _fileStream;
    private readonly MemoryMappedFile? _mmf;
    private readonly MemoryMappedViewAccessor? _accessor;
    private readonly object _syncLock = new();
    private bool _disposed;

    public string FilePath { get; }
    public long Length { get; }

    public MemoryMappedBinarySource(string filePath)
    {
        FilePath = Path.GetFullPath(filePath);
        _fileStream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        Length = _fileStream.Length;

        if (Length > 0)
        {
            _mmf = MemoryMappedFile.CreateFromFile(
                _fileStream,
                mapName: null,
                capacity: 0,
                MemoryMappedFileAccess.Read,
                HandleInheritability.None,
                leaveOpen: true);
            _accessor = _mmf.CreateViewAccessor(0, Length, MemoryMappedFileAccess.Read);
        }
    }

    public int Read(long offset, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (offset < 0 || offset >= Length || destination.IsEmpty || _accessor is null)
            return 0;

        int count = (int)Math.Min(destination.Length, Length - offset);
        lock (_syncLock)
        {
            for (int i = 0; i < count; i++)
            {
                destination[i] = _accessor.ReadByte(offset + i);
            }
        }
        return count;
    }

    public byte ReadByte(long offset)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (offset < 0 || offset >= Length || _accessor is null)
            throw new ArgumentOutOfRangeException(nameof(offset));

        lock (_syncLock)
        {
            return _accessor.ReadByte(offset);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _accessor?.Dispose();
        _mmf?.Dispose();
        _fileStream.Dispose();
    }
}

