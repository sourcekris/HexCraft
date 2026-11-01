using System.Collections.Generic;

namespace HexCraft.Templates.Evaluation;

public sealed record ByteColorInterval(
    long StartOffset,
    long Length,
    string ColorHex,
    string Label);

/// <summary>
/// A node in the evaluated 010 Editor Binary Template result tree.
/// Maps directly to the Template Results TreeView and Hex View color overlays.
/// </summary>
public sealed class TemplateResultNode
{
    public string Name { get; set; } = "";
    public string TypeName { get; set; } = "";
    public string DisplayValue { get; set; } = "";
    public long StartOffset { get; set; }
    public long ByteLength { get; set; }
    public string ColorHex { get; set; } = "";
    public string Comment { get; set; } = "";
    public bool IsExpanded { get; set; } = true;
    public List<TemplateResultNode> Children { get; } = new();

    public string OffsetHex => $"0x{StartOffset:X8}";
    public string SizeText => ByteLength == 1 ? "1 B" : $"{ByteLength:N0} B (0x{ByteLength:X})";
}

public sealed record TemplateExecutionResult(
    bool Success,
    string? ErrorMessage,
    IReadOnlyList<TemplateResultNode> RootNodes,
    IReadOnlyList<ByteColorInterval> ColorIntervals,
    IReadOnlyList<string> ConsoleOutput,
    long BytesParsed);

