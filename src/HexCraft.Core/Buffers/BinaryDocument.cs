using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HexCraft.Core.Buffers;

public enum PieceSourceType
{
    Original,
    Added
}

public readonly record struct Piece(PieceSourceType Source, long SourceOffset, long Length)
{
    public bool IsEmpty => Length <= 0;
}

public sealed record Bookmark(long Offset, long Length, string Name, string ColorHex, string Comment = "");

/// <summary>
/// Memory-safe, Piece-Table backed binary document supporting instant large file loading,
/// byte overwrite, insertion, deletion, undo/redo, bookmarks, and pattern search.
/// </summary>
public sealed class BinaryDocument : IDisposable
{
    private IBinarySource _originalSource;
    private readonly List<byte> _addBuffer = new();
    private List<Piece> _pieces = new();
    private readonly Stack<List<Piece>> _undoStack = new();
    private readonly Stack<List<Piece>> _redoStack = new();
    private readonly HashSet<long> _modifiedOffsets = new();

    public string? FilePath { get; private set; }
    public string DisplayName => string.IsNullOrEmpty(FilePath) ? "Untitled.bin" : Path.GetFileName(FilePath);
    public bool IsModified => _undoStack.Count > 0;
    public List<Bookmark> Bookmarks { get; } = new();

    public event EventHandler? DocumentChanged;

    public BinaryDocument(byte[] initialData, string? filePath = null)
        : this(new MemoryBinarySource(initialData), filePath)
    {
    }

    public BinaryDocument(IBinarySource source, string? filePath = null)
    {
        _originalSource = source ?? throw new ArgumentNullException(nameof(source));
        FilePath = filePath;
        if (_originalSource.Length > 0)
        {
            _pieces.Add(new Piece(PieceSourceType.Original, 0, _originalSource.Length));
        }
    }

    public static BinaryDocument OpenFile(string filePath)
    {
        var source = new MemoryMappedBinarySource(filePath);
        return new BinaryDocument(source, filePath);
    }

    public long Length
    {
        get
        {
            long total = 0;
            for (int i = 0; i < _pieces.Count; i++)
                total += _pieces[i].Length;
            return total;
        }
    }

    public bool CanUndo => _undoStack.Count > 0;
    public bool CanRedo => _redoStack.Count > 0;

    public bool IsOffsetModified(long offset) => _modifiedOffsets.Contains(offset);

    public byte ReadByte(long offset)
    {
        if (offset < 0 || offset >= Length)
            throw new ArgumentOutOfRangeException(nameof(offset));

        long current = 0;
        for (int i = 0; i < _pieces.Count; i++)
        {
            var piece = _pieces[i];
            if (offset < current + piece.Length)
            {
                long rel = offset - current;
                return piece.Source == PieceSourceType.Original
                    ? _originalSource.ReadByte(piece.SourceOffset + rel)
                    : _addBuffer[(int)(piece.SourceOffset + rel)];
            }
            current += piece.Length;
        }

        throw new ArgumentOutOfRangeException(nameof(offset));
    }

    public int ReadBytes(long offset, Span<byte> destination)
    {
        if (offset < 0 || destination.IsEmpty)
            return 0;

        long docLen = Length;
        if (offset >= docLen)
            return 0;

        int totalToRead = (int)Math.Min(destination.Length, docLen - offset);
        int written = 0;
        long currentDocPos = 0;

        for (int i = 0; i < _pieces.Count && written < totalToRead; i++)
        {
            var piece = _pieces[i];
            long pieceEnd = currentDocPos + piece.Length;

            if (offset + written < pieceEnd)
            {
                long pieceRelOffset = (offset + written) - currentDocPos;
                int chunk = (int)Math.Min(totalToRead - written, piece.Length - pieceRelOffset);
                Span<byte> targetSlice = destination.Slice(written, chunk);

                if (piece.Source == PieceSourceType.Original)
                {
                    _originalSource.Read(piece.SourceOffset + pieceRelOffset, targetSlice);
                }
                else
                {
                    int addIndex = (int)(piece.SourceOffset + pieceRelOffset);
                    for (int k = 0; k < chunk; k++)
                        targetSlice[k] = _addBuffer[addIndex + k];
                }

                written += chunk;
            }

            currentDocPos = pieceEnd;
        }

        return written;
    }

    public byte[] ReadBytes(long offset, int count)
    {
        if (count <= 0 || offset < 0 || offset >= Length)
            return Array.Empty<byte>();

        int actual = (int)Math.Min(count, Length - offset);
        byte[] buffer = new byte[actual];
        int read = ReadBytes(offset, buffer);
        return read == actual ? buffer : buffer[..read];
    }

    public void WriteByte(long offset, byte value)
    {
        OverwriteBytes(offset, new ReadOnlySpan<byte>(ref value));
    }

    public void OverwriteBytes(long offset, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        if (offset < 0 || offset > Length)
            throw new ArgumentOutOfRangeException(nameof(offset));

        SaveUndoSnapshot();

        long deleteLen = Math.Min(data.Length, Length - offset);
        if (deleteLen > 0)
        {
            DeleteRangeInternal(offset, deleteLen);
        }
        InsertBytesInternal(offset, data);

        for (int i = 0; i < data.Length; i++)
        {
            _modifiedOffsets.Add(offset + i);
        }

        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    public void InsertBytes(long offset, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        if (offset < 0 || offset > Length)
            throw new ArgumentOutOfRangeException(nameof(offset));

        SaveUndoSnapshot();
        InsertBytesInternal(offset, data);

        for (int i = 0; i < data.Length; i++)
        {
            _modifiedOffsets.Add(offset + i);
        }

        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    public void DeleteBytes(long offset, long count)
    {
        if (count <= 0) return;
        if (offset < 0 || offset + count > Length)
            throw new ArgumentOutOfRangeException(nameof(offset));

        SaveUndoSnapshot();
        DeleteRangeInternal(offset, count);
        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Undo()
    {
        if (!CanUndo) return;
        _redoStack.Push(new List<Piece>(_pieces));
        _pieces = _undoStack.Pop();
        if (_undoStack.Count == 0)
            _modifiedOffsets.Clear();
        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Redo()
    {
        if (!CanRedo) return;
        _undoStack.Push(new List<Piece>(_pieces));
        _pieces = _redoStack.Pop();
        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Save(string? targetPath = null)
    {
        string destination = targetPath ?? FilePath ?? throw new InvalidOperationException("No target file path specified.");
        string fullDest = Path.GetFullPath(destination);
        string tempPath = fullDest + ".hexcraft.tmp";

        using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            byte[] chunk = new byte[64 * 1024];
            long offset = 0;
            long total = Length;
            while (offset < total)
            {
                int read = ReadBytes(offset, chunk);
                if (read <= 0) break;
                fs.Write(chunk, 0, read);
                offset += read;
            }
        }

        // If overwriting the currently memory-mapped file, release original handle first
        bool sameFile = !string.IsNullOrEmpty(FilePath) &&
                        string.Equals(Path.GetFullPath(FilePath), fullDest, StringComparison.OrdinalIgnoreCase);

        if (sameFile)
        {
            _originalSource.Dispose();
        }

        File.Move(tempPath, fullDest, overwrite: true);

        _originalSource.Dispose();
        _originalSource = new MemoryMappedBinarySource(fullDest);
        FilePath = fullDest;
        _addBuffer.Clear();
        _pieces.Clear();
        if (_originalSource.Length > 0)
        {
            _pieces.Add(new Piece(PieceSourceType.Original, 0, _originalSource.Length));
        }
        _undoStack.Clear();
        _redoStack.Clear();
        _modifiedOffsets.Clear();

        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Searches for a byte pattern starting at startOffset. Returns -1 if not found.
    /// </summary>
    public long FindPattern(ReadOnlySpan<byte> pattern, long startOffset = 0)
    {
        if (pattern.IsEmpty || startOffset < 0 || startOffset + pattern.Length > Length)
            return -1;

        const int ChunkSize = 64 * 1024;
        int overlap = Math.Max(0, pattern.Length - 1);
        byte[] buffer = new byte[ChunkSize + overlap];

        long pos = startOffset;
        long total = Length;
        while (pos <= total - pattern.Length)
        {
            int toRead = (int)Math.Min(buffer.Length, total - pos);
            int read = ReadBytes(pos, buffer.AsSpan(0, toRead));
            if (read < pattern.Length)
                break;

            int matchIdx = buffer.AsSpan(0, read).IndexOf(pattern);
            if (matchIdx >= 0)
                return pos + matchIdx;

            pos += Math.Max(1, read - overlap);
        }

        return -1;
    }

    private void SaveUndoSnapshot()
    {
        _undoStack.Push(new List<Piece>(_pieces));
        _redoStack.Clear();
    }

    private void InsertBytesInternal(long offset, ReadOnlySpan<byte> data)
    {
        long addStart = _addBuffer.Count;
        for (int i = 0; i < data.Length; i++)
            _addBuffer.Add(data[i]);

        var newPiece = new Piece(PieceSourceType.Added, addStart, data.Length);

        if (_pieces.Count == 0)
        {
            _pieces.Add(newPiece);
            return;
        }

        SplitAt(offset, out int insertIndex);
        _pieces.Insert(insertIndex, newPiece);
    }

    private void DeleteRangeInternal(long offset, long count)
    {
        SplitAt(offset, out int startIndex);
        SplitAt(offset + count, out int endIndex);

        int removeCount = endIndex - startIndex;
        if (removeCount > 0)
        {
            _pieces.RemoveRange(startIndex, removeCount);
        }
    }

    private void SplitAt(long offset, out int pieceIndex)
    {
        long current = 0;
        for (int i = 0; i < _pieces.Count; i++)
        {
            var piece = _pieces[i];
            if (offset == current)
            {
                pieceIndex = i;
                return;
            }
            if (offset > current && offset < current + piece.Length)
            {
                long leftLen = offset - current;
                long rightLen = piece.Length - leftLen;

                var left = new Piece(piece.Source, piece.SourceOffset, leftLen);
                var right = new Piece(piece.Source, piece.SourceOffset + leftLen, rightLen);

                _pieces[i] = left;
                _pieces.Insert(i + 1, right);
                pieceIndex = i + 1;
                return;
            }
            current += piece.Length;
        }

        pieceIndex = _pieces.Count;
    }

    public void Dispose()
    {
        _originalSource.Dispose();
    }
}

