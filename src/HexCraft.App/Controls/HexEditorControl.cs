using System;
using System.Collections.Generic;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using HexCraft.Core.Buffers;
using HexCraft.Templates.Evaluation;

namespace HexCraft.App.Controls;

public sealed record CursorChangedEventArgs(long Offset, long SelectionStart, long SelectionLength);

/// <summary>
/// Custom hardware-accelerated, virtualized Hex + ASCII Editor control for Avalonia UI.
/// Renders only visible rows so multi-gigabyte files scroll at 60+ FPS with zero lag.
/// Supports nibble-level hex editing, ASCII editing, selection highlighting, and .bt template color intervals.
/// </summary>
public sealed class HexEditorControl : Control
{
    private BinaryDocument? _document;
    private IReadOnlyList<ByteColorInterval> _colorIntervals = Array.Empty<ByteColorInterval>();

    private int _bytesPerRow = 16;
    private long _scrollRowOffset;
    private long _cursorOffset;
    private long _selectionAnchor = -1;
    private bool _editingAsciiColumn;
    private int _pendingHighNibble = -1;

    private const double HeaderHeight = 28.0;
    private const double RowHeight = 21.0;
    private const double CharWidth = 8.4;
    private const double AddressColumnWidth = 92.0;
    private const double ColumnGap = 18.0;

    private static readonly Typeface MonoTypeface = new("Cascadia Mono, Consolas, JetBrains Mono, DejaVu Sans Mono, monospace");
    private static readonly IBrush BgBrush = new SolidColorBrush(Color.Parse("#14171D"));
    private static readonly IBrush HeaderBgBrush = new SolidColorBrush(Color.Parse("#1C2029"));
    private static readonly IBrush GutterBgBrush = new SolidColorBrush(Color.Parse("#181B22"));
    private static readonly IBrush GridLineBrush = new SolidColorBrush(Color.Parse("#282E3B"));
    private static readonly IBrush AddressTextBrush = new SolidColorBrush(Color.Parse("#56B6C2"));
    private static readonly IBrush HeaderTextBrush = new SolidColorBrush(Color.Parse("#7F848E"));
    private static readonly IBrush ByteTextBrush = new SolidColorBrush(Color.Parse("#D7DAE0"));
    private static readonly IBrush NullByteTextBrush = new SolidColorBrush(Color.Parse("#4B5263"));
    private static readonly IBrush ModifiedByteTextBrush = new SolidColorBrush(Color.Parse("#E06C75"));
    private static readonly IBrush AsciiTextBrush = new SolidColorBrush(Color.Parse("#98C379"));
    private static readonly IBrush SelectionBrush = new SolidColorBrush(Color.Parse("#3D61AFEF"));
    private static readonly IBrush CursorPrimaryBrush = new SolidColorBrush(Color.Parse("#E5C07B"));
    private static readonly IBrush CursorSecondaryBrush = new SolidColorBrush(Color.Parse("#45E5C07B"));
    private static readonly IPen CursorOutlinePen = new Pen(new SolidColorBrush(Color.Parse("#E5C07B")), 1.5);

    private readonly Dictionary<string, IBrush> _templateBrushCache = new(StringComparer.OrdinalIgnoreCase);

    public event EventHandler<CursorChangedEventArgs>? CursorChanged;
    public event EventHandler? BytesModified;

    public HexEditorControl()
    {
        Focusable = true;
        ClipToBounds = true;
    }

    public BinaryDocument? Document
    {
        get => _document;
        set
        {
            _document = value;
            _cursorOffset = 0;
            _selectionAnchor = 0;
            _scrollRowOffset = 0;
            _pendingHighNibble = -1;
            InvalidateVisual();
            RaiseCursorChanged();
        }
    }

    public IReadOnlyList<ByteColorInterval> ColorIntervals
    {
        get => _colorIntervals;
        set
        {
            _colorIntervals = value ?? Array.Empty<ByteColorInterval>();
            InvalidateVisual();
        }
    }

    public int BytesPerRow
    {
        get => _bytesPerRow;
        set
        {
            _bytesPerRow = Math.Clamp(value, 8, 32);
            InvalidateVisual();
        }
    }

    public long CursorOffset => _cursorOffset;

    public (long Start, long Length) GetSelectionRange()
    {
        if (_document is null || _document.Length == 0)
            return (0, 0);

        if (_selectionAnchor < 0 || _selectionAnchor == _cursorOffset)
            return (_cursorOffset, 1);

        long start = Math.Min(_cursorOffset, _selectionAnchor);
        long end = Math.Max(_cursorOffset, _selectionAnchor);
        return (start, end - start + 1);
    }

    public void SelectRange(long offset, long length)
    {
        if (_document is null || _document.Length == 0)
            return;

        long clampedStart = Math.Clamp(offset, 0, _document.Length - 1);
        long clampedEnd = Math.Clamp(clampedStart + Math.Max(1, length) - 1, 0, _document.Length - 1);

        _selectionAnchor = clampedStart;
        _cursorOffset = clampedEnd;
        _pendingHighNibble = -1;
        EnsureCursorVisible();
        InvalidateVisual();
        RaiseCursorChanged();
    }

    public void JumpToOffset(long offset)
    {
        if (_document is null || _document.Length == 0)
            return;

        _cursorOffset = Math.Clamp(offset, 0, _document.Length - 1);
        _selectionAnchor = _cursorOffset;
        _pendingHighNibble = -1;
        EnsureCursorVisible();
        InvalidateVisual();
        RaiseCursorChanged();
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        Rect bounds = Bounds;
        context.FillRectangle(BgBrush, new Rect(0, 0, bounds.Width, bounds.Height));

        // Left address gutter & top column header backgrounds
        context.FillRectangle(GutterBgBrush, new Rect(0, HeaderHeight, AddressColumnWidth, Math.Max(0, bounds.Height - HeaderHeight)));
        context.FillRectangle(HeaderBgBrush, new Rect(0, 0, bounds.Width, HeaderHeight));

        double hexStartX = AddressColumnWidth + ColumnGap;
        double hexByteStep = CharWidth * 3.0;
        double midGroupGap = CharWidth * 0.8;
        double hexWidth = _bytesPerRow * hexByteStep + midGroupGap;
        double asciiStartX = hexStartX + hexWidth + ColumnGap;

        // Draw column headers
        DrawText(context, "OFFSET (HEX)", 10, 6, HeaderTextBrush, 11.5, FontWeight.SemiBold);
        for (int col = 0; col < _bytesPerRow; col++)
        {
            double x = GetHexColumnX(hexStartX, col, hexByteStep, midGroupGap);
            DrawText(context, $"{col:X2}", x, 6, HeaderTextBrush, 11.5, FontWeight.SemiBold);
        }
        DrawText(context, "DECODED ASCII", asciiStartX, 6, HeaderTextBrush, 11.5, FontWeight.SemiBold);

        // Separator lines
        var sepPen = new Pen(GridLineBrush, 1);
        context.DrawLine(sepPen, new Point(0, HeaderHeight), new Point(bounds.Width, HeaderHeight));
        context.DrawLine(sepPen, new Point(AddressColumnWidth, 0), new Point(AddressColumnWidth, bounds.Height));
        context.DrawLine(sepPen, new Point(asciiStartX - ColumnGap * 0.5, 0), new Point(asciiStartX - ColumnGap * 0.5, bounds.Height));

        if (_document is null || _document.Length == 0)
        {
            DrawText(context, "Empty document — open a binary file or click 'Load Sample Firmware'.", hexStartX, HeaderHeight + 20, HeaderTextBrush, 13);
            return;
        }

        int visibleRows = Math.Max(1, (int)((bounds.Height - HeaderHeight) / RowHeight));
        long totalRows = (_document.Length + _bytesPerRow - 1) / _bytesPerRow;
        _scrollRowOffset = Math.Clamp(_scrollRowOffset, 0, Math.Max(0, totalRows - 1));

        var (selStart, selLen) = GetSelectionRange();
        long selEnd = selStart + selLen - 1;

        Span<byte> rowBuf = stackalloc byte[_bytesPerRow];

        for (int r = 0; r < visibleRows; r++)
        {
            long rowIdx = _scrollRowOffset + r;
            long rowBaseOffset = rowIdx * _bytesPerRow;
            if (rowBaseOffset >= _document.Length)
                break;

            double y = HeaderHeight + r * RowHeight;
            int read = _document.ReadBytes(rowBaseOffset, rowBuf);

            // Draw row offset
            DrawText(context, $"{rowBaseOffset:X8}", 10, y + 3, AddressTextBrush, 12.5);

            for (int c = 0; c < read; c++)
            {
                long byteOffset = rowBaseOffset + c;
                byte b = rowBuf[c];
                double hx = GetHexColumnX(hexStartX, c, hexByteStep, midGroupGap);
                double ax = asciiStartX + c * (CharWidth + 1.0);

                // 1. Template color interval overlay
                string? tplColor = FindTemplateColorForOffset(byteOffset);
                if (!string.IsNullOrEmpty(tplColor))
                {
                    var tplBrush = GetTemplateOverlayBrush(tplColor);
                    context.FillRectangle(tplBrush, new Rect(hx - 2, y + 1, CharWidth * 2 + 4, RowHeight - 2));
                    context.FillRectangle(tplBrush, new Rect(ax - 1, y + 1, CharWidth + 1, RowHeight - 2));
                }

                // 2. Selection highlight
                if (byteOffset >= selStart && byteOffset <= selEnd)
                {
                    context.FillRectangle(SelectionBrush, new Rect(hx - 2, y + 1, CharWidth * 2 + 4, RowHeight - 2));
                    context.FillRectangle(SelectionBrush, new Rect(ax - 1, y + 1, CharWidth + 1, RowHeight - 2));
                }

                // 3. Active cursor highlight
                if (byteOffset == _cursorOffset)
                {
                    var hexCursorRect = new Rect(hx - 2, y + 1, CharWidth * 2 + 4, RowHeight - 2);
                    var asciiCursorRect = new Rect(ax - 1, y + 1, CharWidth + 1, RowHeight - 2);

                    if (!_editingAsciiColumn)
                    {
                        context.FillRectangle(CursorPrimaryBrush, hexCursorRect);
                        context.DrawRectangle(CursorOutlinePen, asciiCursorRect);
                    }
                    else
                    {
                        context.FillRectangle(CursorPrimaryBrush, asciiCursorRect);
                        context.DrawRectangle(CursorOutlinePen, hexCursorRect);
                    }
                }

                // 4. Hex digits
                bool isCursorPrimaryHex = byteOffset == _cursorOffset && !_editingAsciiColumn;
                IBrush fgHex = isCursorPrimaryHex
                    ? BgBrush
                    : _document.IsOffsetModified(byteOffset)
                        ? ModifiedByteTextBrush
                        : b == 0 ? NullByteTextBrush : ByteTextBrush;

                DrawText(context, b.ToString("X2"), hx, y + 3, fgHex, 12.5,
                    isCursorPrimaryHex || _document.IsOffsetModified(byteOffset) ? FontWeight.Bold : FontWeight.Normal);

                // 5. ASCII character
                bool isCursorPrimaryAscii = byteOffset == _cursorOffset && _editingAsciiColumn;
                char ch = b is >= 32 and < 127 ? (char)b : '.';
                IBrush fgAscii = isCursorPrimaryAscii
                    ? BgBrush
                    : b is >= 32 and < 127 ? AsciiTextBrush : NullByteTextBrush;

                DrawText(context, ch.ToString(), ax, y + 3, fgAscii, 12.5);
            }
        }

        // Draw scrollbar / minimap indicator on right edge
        DrawScrollbar(context, bounds, totalRows, visibleRows);
    }

    private void DrawScrollbar(DrawingContext context, Rect bounds, long totalRows, int visibleRows)
    {
        if (totalRows <= 0 || _document is null || _document.Length == 0) return;
        double trackWidth = 14;
        double trackX = bounds.Width - trackWidth - 2;
        double trackY = HeaderHeight + 2;
        double trackH = Math.Max(20, bounds.Height - HeaderHeight - 4);

        context.FillRectangle(GutterBgBrush, new Rect(trackX, trackY, trackWidth, trackH));

        // Render template color intervals on minimap
        double docLen = Math.Max(1.0, _document.Length);
        foreach (var iv in _colorIntervals)
        {
            double y0 = trackY + (iv.StartOffset / docLen) * trackH;
            double h = Math.Max(2.0, (iv.Length / docLen) * trackH);
            if (!string.IsNullOrEmpty(iv.ColorHex) && Color.TryParse(iv.ColorHex, out Color c))
            {
                context.FillRectangle(new SolidColorBrush(Color.FromArgb(140, c.R, c.G, c.B)),
                    new Rect(trackX + 1, y0, trackWidth - 2, Math.Min(h, trackY + trackH - y0)));
            }
        }

        // Render bookmark markers on minimap
        foreach (var bm in _document.Bookmarks)
        {
            double y0 = trackY + (bm.Offset / docLen) * trackH;
            if (!string.IsNullOrEmpty(bm.ColorHex) && Color.TryParse(bm.ColorHex, out Color c))
            {
                context.FillRectangle(new SolidColorBrush(c), new Rect(trackX, y0, trackWidth, 3));
            }
        }

        double thumbRatio = Math.Clamp((double)visibleRows / totalRows, 0.04, 1.0);
        double thumbH = Math.Max(18, trackH * thumbRatio);
        double posRatio = totalRows > 1 ? (double)_scrollRowOffset / (totalRows - 1) : 0;
        double thumbY = trackY + (trackH - thumbH) * Math.Clamp(posRatio, 0, 1);

        context.FillRectangle(new SolidColorBrush(Color.FromArgb(120, 86, 182, 194)),
            new Rect(trackX + 1, thumbY, trackWidth - 2, thumbH), 3);
        context.DrawRectangle(new Pen(AddressTextBrush, 1),
            new Rect(trackX + 1, thumbY, trackWidth - 2, thumbH), 3);
    }

    protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
    {
        base.OnPointerWheelChanged(e);
        if (_document is null || _document.Length == 0) return;

        long totalRows = (_document.Length + _bytesPerRow - 1) / _bytesPerRow;
        long delta = (long)(-e.Delta.Y * 3);
        _scrollRowOffset = Math.Clamp(_scrollRowOffset + delta, 0, Math.Max(0, totalRows - 1));
        InvalidateVisual();
        e.Handled = true;
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        Focus();
        if (_document is null || _document.Length == 0) return;

        Point pt = e.GetPosition(this);
        if (TryHitTestOffset(pt, out long hitOffset, out bool inAscii))
        {
            _editingAsciiColumn = inAscii;
            _cursorOffset = hitOffset;
            if (!e.KeyModifiers.HasFlag(KeyModifiers.Shift))
                _selectionAnchor = hitOffset;
            _pendingHighNibble = -1;
            InvalidateVisual();
            RaiseCursorChanged();
        }
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        if (_document is null || _document.Length == 0) return;

        var props = e.GetCurrentPoint(this).Properties;
        if (props.IsLeftButtonPressed)
        {
            Point pt = e.GetPosition(this);
            if (TryHitTestOffset(pt, out long hitOffset, out _))
            {
                if (hitOffset != _cursorOffset)
                {
                    _cursorOffset = hitOffset;
                    InvalidateVisual();
                    RaiseCursorChanged();
                }
            }
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (_document is null || _document.Length == 0) return;

        bool shift = e.KeyModifiers.HasFlag(KeyModifiers.Shift);
        bool ctrl = e.KeyModifiers.HasFlag(KeyModifiers.Control);

        if (ctrl && e.Key == Key.Z)
        {
            _document.Undo();
            BytesModified?.Invoke(this, EventArgs.Empty);
            InvalidateVisual();
            e.Handled = true;
            return;
        }
        if (ctrl && e.Key == Key.Y)
        {
            _document.Redo();
            BytesModified?.Invoke(this, EventArgs.Empty);
            InvalidateVisual();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Tab)
        {
            _editingAsciiColumn = !_editingAsciiColumn;
            _pendingHighNibble = -1;
            InvalidateVisual();
            e.Handled = true;
            return;
        }

        long newOffset = _cursorOffset;
        bool moved = true;
        int visibleRows = Math.Max(1, (int)((Bounds.Height - HeaderHeight) / RowHeight));

        switch (e.Key)
        {
            case Key.Left:
                newOffset = Math.Max(0, _cursorOffset - 1);
                break;
            case Key.Right:
                newOffset = Math.Min(_document.Length - 1, _cursorOffset + 1);
                break;
            case Key.Up:
                newOffset = Math.Max(0, _cursorOffset - _bytesPerRow);
                break;
            case Key.Down:
                newOffset = Math.Min(_document.Length - 1, _cursorOffset + _bytesPerRow);
                break;
            case Key.PageUp:
                newOffset = Math.Max(0, _cursorOffset - _bytesPerRow * visibleRows);
                break;
            case Key.PageDown:
                newOffset = Math.Min(_document.Length - 1, _cursorOffset + _bytesPerRow * visibleRows);
                break;
            case Key.Home:
                newOffset = ctrl ? 0 : (_cursorOffset / _bytesPerRow) * _bytesPerRow;
                break;
            case Key.End:
                newOffset = ctrl ? _document.Length - 1 : Math.Min(_document.Length - 1, ((_cursorOffset / _bytesPerRow) + 1) * _bytesPerRow - 1);
                break;
            case Key.Delete:
                if (_document.Length > 1)
                {
                    var (s, l) = GetSelectionRange();
                    _document.DeleteBytes(s, Math.Min(l, _document.Length - 1));
                    _cursorOffset = Math.Clamp(s, 0, _document.Length - 1);
                    _selectionAnchor = _cursorOffset;
                    BytesModified?.Invoke(this, EventArgs.Empty);
                    InvalidateVisual();
                    RaiseCursorChanged();
                }
                e.Handled = true;
                return;
            default:
                moved = false;
                break;
        }

        if (moved)
        {
            _cursorOffset = newOffset;
            if (!shift)
                _selectionAnchor = _cursorOffset;
            _pendingHighNibble = -1;
            EnsureCursorVisible();
            InvalidateVisual();
            RaiseCursorChanged();
            e.Handled = true;
            return;
        }

        // Handle Hex nibble entry when in Hex column
        if (!_editingAsciiColumn && !ctrl)
        {
            int nibble = KeyToHexNibble(e.Key);
            if (nibble >= 0)
            {
                byte current = _document.ReadByte(_cursorOffset);
                if (_pendingHighNibble < 0)
                {
                    _pendingHighNibble = nibble;
                    byte updated = (byte)((nibble << 4) | (current & 0x0F));
                    _document.WriteByte(_cursorOffset, updated);
                }
                else
                {
                    byte updated = (byte)((_pendingHighNibble << 4) | nibble);
                    _document.WriteByte(_cursorOffset, updated);
                    _pendingHighNibble = -1;
                    if (_cursorOffset + 1 < _document.Length)
                    {
                        _cursorOffset++;
                        _selectionAnchor = _cursorOffset;
                        EnsureCursorVisible();
                    }
                }
                BytesModified?.Invoke(this, EventArgs.Empty);
                InvalidateVisual();
                RaiseCursorChanged();
                e.Handled = true;
            }
        }
    }

    protected override void OnTextInput(TextInputEventArgs e)
    {
        base.OnTextInput(e);
        if (_document is null || _document.Length == 0 || !_editingAsciiColumn || string.IsNullOrEmpty(e.Text))
            return;

        char ch = e.Text[0];
        if (ch >= 32 && ch < 127)
        {
            _document.WriteByte(_cursorOffset, (byte)ch);
            if (_cursorOffset + 1 < _document.Length)
            {
                _cursorOffset++;
                _selectionAnchor = _cursorOffset;
                EnsureCursorVisible();
            }
            BytesModified?.Invoke(this, EventArgs.Empty);
            InvalidateVisual();
            RaiseCursorChanged();
            e.Handled = true;
        }
    }

    private bool TryHitTestOffset(Point pt, out long offset, out bool inAscii)
    {
        offset = 0;
        inAscii = false;
        if (_document is null || _document.Length == 0 || pt.Y < HeaderHeight)
            return false;

        long row = _scrollRowOffset + (long)((pt.Y - HeaderHeight) / RowHeight);
        double hexStartX = AddressColumnWidth + ColumnGap;
        double hexByteStep = CharWidth * 3.0;
        double midGroupGap = CharWidth * 0.8;
        double hexWidth = _bytesPerRow * hexByteStep + midGroupGap;
        double asciiStartX = hexStartX + hexWidth + ColumnGap;

        int col;
        if (pt.X >= asciiStartX)
        {
            inAscii = true;
            col = (int)((pt.X - asciiStartX) / (CharWidth + 1.0));
        }
        else if (pt.X >= hexStartX - 4)
        {
            inAscii = false;
            double relX = pt.X - hexStartX;
            if (relX > (_bytesPerRow / 2) * hexByteStep)
                relX -= midGroupGap;
            col = (int)(relX / hexByteStep);
        }
        else
        {
            return false;
        }

        col = Math.Clamp(col, 0, _bytesPerRow - 1);
        long candidate = row * _bytesPerRow + col;
        if (candidate < 0 || candidate >= _document.Length)
            return false;

        offset = candidate;
        return true;
    }

    private void EnsureCursorVisible()
    {
        long cursorRow = _cursorOffset / _bytesPerRow;
        int visibleRows = Math.Max(1, (int)((Bounds.Height - HeaderHeight) / RowHeight) - 1);

        if (cursorRow < _scrollRowOffset)
            _scrollRowOffset = cursorRow;
        else if (cursorRow >= _scrollRowOffset + visibleRows)
            _scrollRowOffset = cursorRow - visibleRows + 1;
    }

    private string? FindTemplateColorForOffset(long offset)
    {
        if (_document is not null && _document.Bookmarks.Count > 0)
        {
            for (int i = _document.Bookmarks.Count - 1; i >= 0; i--)
            {
                var bm = _document.Bookmarks[i];
                if (offset >= bm.Offset && offset < bm.Offset + bm.Length && !string.IsNullOrEmpty(bm.ColorHex))
                    return bm.ColorHex;
            }
        }

        for (int i = _colorIntervals.Count - 1; i >= 0; i--)
        {
            var iv = _colorIntervals[i];
            if (offset >= iv.StartOffset && offset < iv.StartOffset + iv.Length)
                return iv.ColorHex;
        }
        return null;
    }

    private IBrush GetTemplateOverlayBrush(string hexColor)
    {
        if (_templateBrushCache.TryGetValue(hexColor, out var cached))
            return cached;

        if (Color.TryParse(hexColor, out Color c))
        {
            var semi = new SolidColorBrush(Color.FromArgb(72, c.R, c.G, c.B));
            _templateBrushCache[hexColor] = semi;
            return semi;
        }

        return SelectionBrush;
    }

    private static double GetHexColumnX(double startX, int col, double step, double midGap)
    {
        return startX + col * step + (col >= 8 ? midGap : 0);
    }

    private static void DrawText(
        DrawingContext context,
        string text,
        double x,
        double y,
        IBrush foreground,
        double fontSize,
        FontWeight weight = FontWeight.Normal)
    {
        var ft = new FormattedText(
            text,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            new Typeface(MonoTypeface.FontFamily, FontStyle.Normal, weight),
            fontSize,
            foreground);
        context.DrawText(ft, new Point(x, y));
    }

    private static int KeyToHexNibble(Key key)
    {
        return key switch
        {
            Key.D0 or Key.NumPad0 => 0,
            Key.D1 or Key.NumPad1 => 1,
            Key.D2 or Key.NumPad2 => 2,
            Key.D3 or Key.NumPad3 => 3,
            Key.D4 or Key.NumPad4 => 4,
            Key.D5 or Key.NumPad5 => 5,
            Key.D6 or Key.NumPad6 => 6,
            Key.D7 or Key.NumPad7 => 7,
            Key.D8 or Key.NumPad8 => 8,
            Key.D9 or Key.NumPad9 => 9,
            Key.A => 10,
            Key.B => 11,
            Key.C => 12,
            Key.D => 13,
            Key.E => 14,
            Key.F => 15,
            _ => -1
        };
    }

    private void RaiseCursorChanged()
    {
        var (selStart, selLen) = GetSelectionRange();
        CursorChanged?.Invoke(this, new CursorChangedEventArgs(_cursorOffset, selStart, selLen));
    }
}

