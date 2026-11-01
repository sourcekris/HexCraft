using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using HexCraft.Core.Analysis;
using HexCraft.Core.Buffers;
using HexCraft.Templates.Ast;
using HexCraft.Templates.Parsing;

namespace HexCraft.Templates.Evaluation;

/// <summary>
/// Dynamic runtime value during .bt template evaluation.
/// Can hold an integer, floating-point number, string, array, or struct dictionary.
/// </summary>
public sealed class BtValue
{
    public long IntValue { get; set; }
    public double FloatValue { get; set; }
    public string? StringValue { get; set; }
    public bool IsFloat { get; set; }
    public bool IsString => StringValue is not null;
    public Dictionary<string, BtValue> Members { get; } = new(StringComparer.Ordinal);
    public List<BtValue> Elements { get; } = new();
    public long StartOffset { get; set; }
    public long ByteSize { get; set; }

    public static BtValue FromInt(long v, long offset = 0, long size = 0) =>
        new() { IntValue = v, FloatValue = v, StartOffset = offset, ByteSize = size };

    public static BtValue FromFloat(double d, long offset = 0, long size = 0) =>
        new() { IntValue = (long)d, FloatValue = d, IsFloat = true, StartOffset = offset, ByteSize = size };

    public static BtValue FromString(string s, long offset = 0, long size = 0) =>
        new() { StringValue = s, IntValue = s.Length > 0 ? s[0] : 0, StartOffset = offset, ByteSize = size };

    public bool IsTruthy => IsString ? !string.IsNullOrEmpty(StringValue) : IsFloat ? Math.Abs(FloatValue) > 1e-12 : IntValue != 0;

    public override string ToString()
    {
        if (IsString) return StringValue!;
        if (IsFloat) return FloatValue.ToString("G", CultureInfo.InvariantCulture);
        return IntValue.ToString(CultureInfo.InvariantCulture);
    }
}

/// <summary>
/// AST Interpreter for 010 Editor Binary Templates (.bt).
/// Executes declarations and imperative control-flow statements against a <see cref="BinaryDocument"/>.
/// </summary>
public sealed class BtInterpreter
{
    private readonly BinaryDocument _doc;
    private readonly int _maxLoopIterations;
    private long _cursor;
    private bool _bigEndian;
    private string _defaultBgColor = "";
    private int _stepCount;
    private const int MaxTotalSteps = 100_000;

    // Bitfield state
    private long _bitfieldByteOffset = -1;
    private int _bitfieldBitsRemaining;
    private ulong _bitfieldCurrentValue;

    private readonly Dictionary<string, BtStructDefStmt> _structTypes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, BtEnumDefStmt> _enumTypes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<long, string>> _enumValueNames = new(StringComparer.Ordinal);
    private readonly Dictionary<string, BtTypedefStmt> _typedefs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, BtFunctionDefStmt> _functions = new(StringComparer.Ordinal);

    private readonly Stack<Dictionary<string, BtValue>> _scopes = new();
    private readonly Stack<List<TemplateResultNode>> _nodeContainers = new();
    private readonly List<TemplateResultNode> _rootNodes = new();
    private readonly List<ByteColorInterval> _colorIntervals = new();
    private readonly List<string> _consoleOutput = new();

    private static readonly Dictionary<string, (long BgrValue, string HexColor)> ColorConstants = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cBlack"] = (0x000000, "#1E222A"),
        ["cRed"] = (0x0000FF, "#E06C75"),
        ["cLtRed"] = (0x8080FF, "#FF7B86"),
        ["cDkRed"] = (0x000080, "#9E2A35"),
        ["cGreen"] = (0x00FF00, "#98C379"),
        ["cLtGreen"] = (0x80FF80, "#7EC892"),
        ["cDkGreen"] = (0x008000, "#3B7A57"),
        ["cBlue"] = (0xFF0000, "#61AFEF"),
        ["cLtBlue"] = (0xFF8080, "#56B6C2"),
        ["cDkBlue"] = (0x800000, "#2B5B84"),
        ["cYellow"] = (0x00FFFF, "#E5C07B"),
        ["cLtYellow"] = (0x80FFFF, "#F0D090"),
        ["cDkYellow"] = (0x008080, "#B08D48"),
        ["cPurple"] = (0xFF00FF, "#C678DD"),
        ["cLtPurple"] = (0xFF80FF, "#D896EC"),
        ["cDkPurple"] = (0x800080, "#7E4A9E"),
        ["cAqua"] = (0xFFFF00, "#4EC9B0"),
        ["cLtAqua"] = (0xFFFF80, "#6CDCD0"),
        ["cWhite"] = (0xFFFFFF, "#ABB2BF"),
        ["cLtGray"] = (0xC0C0C0, "#7F848E"),
        ["cGray"] = (0x808080, "#5C6370"),
        ["cDkGray"] = (0x404040, "#3E4451"),
        ["cSilver"] = (0xC0C0C0, "#9DA5B4"),
        ["cNone"] = (-1, "")
    };

    private sealed class BreakException : Exception { }
    private sealed class ContinueException : Exception { }
    private sealed class ReturnException : Exception
    {
        public BtValue Value { get; }
        public ReturnException(BtValue value) => Value = value;
    }

    public BtInterpreter(BinaryDocument doc, int maxLoopIterations = 4096)
    {
        _doc = doc ?? throw new ArgumentNullException(nameof(doc));
        _maxLoopIterations = maxLoopIterations;

        var globalScope = new Dictionary<string, BtValue>(StringComparer.Ordinal);
        foreach (var kvp in ColorConstants)
        {
            globalScope[kvp.Key] = BtValue.FromInt(kvp.Value.BgrValue);
        }
        globalScope["TRUE"] = BtValue.FromInt(1);
        globalScope["FALSE"] = BtValue.FromInt(0);

        _scopes.Push(globalScope);
        _nodeContainers.Push(_rootNodes);
    }

    public static TemplateExecutionResult Execute(BinaryDocument doc, string templateSource)
    {
        try
        {
            var program = BtParser.Parse(templateSource);
            var interpreter = new BtInterpreter(doc);
            return interpreter.Run(program);
        }
        catch (Exception ex)
        {
            return new TemplateExecutionResult(
                Success: false,
                ErrorMessage: ex.Message,
                RootNodes: Array.Empty<TemplateResultNode>(),
                ColorIntervals: Array.Empty<ByteColorInterval>(),
                ConsoleOutput: new[] { $"[Template Error] {ex.Message}" },
                BytesParsed: 0);
        }
    }

    public TemplateExecutionResult Run(BtProgram program)
    {
        try
        {
            foreach (var stmt in program.Statements)
            {
                ExecuteStmt(stmt);
            }

            return new TemplateExecutionResult(
                Success: true,
                ErrorMessage: null,
                RootNodes: _rootNodes,
                ColorIntervals: _colorIntervals,
                ConsoleOutput: _consoleOutput,
                BytesParsed: _cursor);
        }
        catch (ReturnException)
        {
            return new TemplateExecutionResult(
                Success: true,
                ErrorMessage: null,
                RootNodes: _rootNodes,
                ColorIntervals: _colorIntervals,
                ConsoleOutput: _consoleOutput,
                BytesParsed: _cursor);
        }
        catch (Exception ex)
        {
            return new TemplateExecutionResult(
                Success: false,
                ErrorMessage: ex.Message,
                RootNodes: _rootNodes,
                ColorIntervals: _colorIntervals,
                ConsoleOutput: _consoleOutput.Append($"[Runtime Error] {ex.Message}").ToList(),
                BytesParsed: _cursor);
        }
    }

    private void ExecuteStmt(BtStmt stmt)
    {
        if (++_stepCount > MaxTotalSteps)
            throw new InvalidOperationException("Template execution exceeded maximum step limit (possible infinite loop).");

        switch (stmt)
        {
            case BtBlockStmt block:
                foreach (var s in block.Statements)
                    ExecuteStmt(s);
                break;

            case BtExprStmt exprStmt:
                EvaluateExpr(exprStmt.Expression);
                break;

            case BtIfStmt ifStmt:
                if (EvaluateExpr(ifStmt.Condition).IsTruthy)
                    ExecuteStmt(ifStmt.ThenBranch);
                else if (ifStmt.ElseBranch is not null)
                    ExecuteStmt(ifStmt.ElseBranch);
                break;

            case BtWhileStmt whileStmt:
            {
                int iter = 0;
                while (EvaluateExpr(whileStmt.Condition).IsTruthy)
                {
                    if (++iter > _maxLoopIterations)
                        break;
                    try
                    {
                        ExecuteStmt(whileStmt.Body);
                    }
                    catch (ContinueException) { }
                    catch (BreakException) { break; }
                }
                break;
            }

            case BtDoWhileStmt doStmt:
            {
                int iter = 0;
                do
                {
                    if (++iter > _maxLoopIterations)
                        break;
                    try
                    {
                        ExecuteStmt(doStmt.Body);
                    }
                    catch (ContinueException) { }
                    catch (BreakException) { break; }
                } while (EvaluateExpr(doStmt.Condition).IsTruthy);
                break;
            }

            case BtForStmt forStmt:
            {
                if (forStmt.Initializer is not null)
                    ExecuteStmt(forStmt.Initializer);

                int iter = 0;
                while (forStmt.Condition is null || EvaluateExpr(forStmt.Condition).IsTruthy)
                {
                    if (++iter > _maxLoopIterations)
                        break;
                    try
                    {
                        ExecuteStmt(forStmt.Body);
                    }
                    catch (ContinueException) { }
                    catch (BreakException) { break; }

                    if (forStmt.Increment is not null)
                        EvaluateExpr(forStmt.Increment);
                }
                break;
            }

            case BtSwitchStmt switchStmt:
            {
                var targetVal = EvaluateExpr(switchStmt.Value);
                bool matched = false;
                BtSwitchCase? defaultCase = null;

                foreach (var c in switchStmt.Cases)
                {
                    if (c.MatchValue is null)
                    {
                        defaultCase = c;
                        continue;
                    }
                    var caseVal = EvaluateExpr(c.MatchValue);
                    bool isEqual = targetVal.IsString
                        ? string.Equals(targetVal.StringValue, caseVal.StringValue, StringComparison.Ordinal)
                        : targetVal.IntValue == caseVal.IntValue;

                    if (isEqual)
                    {
                        matched = true;
                        try
                        {
                            foreach (var s in c.Statements)
                                ExecuteStmt(s);
                        }
                        catch (BreakException) { }
                        break;
                    }
                }

                if (!matched && defaultCase is not null)
                {
                    try
                    {
                        foreach (var s in defaultCase.Statements)
                            ExecuteStmt(s);
                    }
                    catch (BreakException) { }
                }
                break;
            }

            case BtBreakStmt:
                throw new BreakException();

            case BtContinueStmt:
                throw new ContinueException();

            case BtReturnStmt retStmt:
            {
                var val = retStmt.Value is not null ? EvaluateExpr(retStmt.Value) : BtValue.FromInt(0);
                throw new ReturnException(val);
            }

            case BtTypedefStmt typedefStmt:
                _typedefs[typedefStmt.AliasName] = typedefStmt;
                break;

            case BtEnumDefStmt enumStmt:
                RegisterEnum(enumStmt);
                if (!string.IsNullOrEmpty(enumStmt.InstanceName))
                {
                    ExecuteVarDecl(new BtVarDeclStmt(
                        IsLocal: false,
                        TypeName: enumStmt.EnumName,
                        Name: enumStmt.InstanceName,
                        ArrayLength: null,
                        BitfieldWidth: null,
                        Initializer: null,
                        Attributes: enumStmt.Attributes,
                        Line: enumStmt.Line));
                }
                break;

            case BtStructDefStmt structStmt:
                _structTypes[structStmt.TypeName] = structStmt;
                if (!string.IsNullOrEmpty(structStmt.InstanceName))
                {
                    ExecuteVarDecl(new BtVarDeclStmt(
                        IsLocal: false,
                        TypeName: structStmt.TypeName,
                        Name: structStmt.InstanceName,
                        ArrayLength: structStmt.InstanceArrayLength,
                        BitfieldWidth: null,
                        Initializer: null,
                        Attributes: structStmt.Attributes,
                        Line: structStmt.Line));
                }
                break;

            case BtFunctionDefStmt funcStmt:
                _functions[funcStmt.Name] = funcStmt;
                break;

            case BtVarDeclStmt varDecl:
                ExecuteVarDecl(varDecl);
                break;
        }
    }

    private void RegisterEnum(BtEnumDefStmt enumStmt)
    {
        _enumTypes[enumStmt.EnumName] = enumStmt;
        var map = new Dictionary<long, string>();
        long nextVal = 0;

        foreach (var member in enumStmt.Members)
        {
            if (member.ValueExpr is not null)
                nextVal = EvaluateExpr(member.ValueExpr).IntValue;

            map[nextVal] = member.Name;
            _scopes.Peek()[member.Name] = BtValue.FromInt(nextVal);
            nextVal++;
        }

        _enumValueNames[enumStmt.EnumName] = map;
    }

    private void ExecuteVarDecl(BtVarDeclStmt decl)
    {
        if (decl.IsLocal)
        {
            BtValue val = decl.Initializer is not null
                ? EvaluateExpr(decl.Initializer)
                : BtValue.FromInt(0);
            SetVariable(decl.Name, val);
            return;
        }

        // Resolve typedef aliases
        string resolvedType = decl.TypeName;
        int? typedefArrayLen = null;
        int guard = 0;
        while (_typedefs.TryGetValue(resolvedType, out var td) && guard++ < 8)
        {
            resolvedType = td.ExistingType;
            if (td.FixedArraySize.HasValue)
                typedefArrayLen = td.FixedArraySize;
        }

        int? arrayLen = null;
        if (decl.ArrayLength is not null)
            arrayLen = (int)Math.Max(0, EvaluateExpr(decl.ArrayLength).IntValue);
        else if (typedefArrayLen.HasValue)
            arrayLen = typedefArrayLen.Value;

        string colorHex = ResolveColorHex(decl.Attributes);
        string comment = ResolveComment(decl.Attributes);
        bool hexFormat = string.Equals(decl.Attributes?.Format, "hex", StringComparison.OrdinalIgnoreCase);

        // Handle bitfields
        if (decl.BitfieldWidth.HasValue && decl.BitfieldWidth.Value > 0)
        {
            ExecuteBitfieldDecl(decl, resolvedType, decl.BitfieldWidth.Value, colorHex, comment);
            return;
        }
        else
        {
            // Reset active bitfield byte when a normal field is read
            _bitfieldBitsRemaining = 0;
        }

        // Struct or Union instance
        if (_structTypes.TryGetValue(resolvedType, out var structDef))
        {
            if (arrayLen.HasValue)
            {
                var arrVal = new BtValue { StartOffset = _cursor };
                var arrNode = new TemplateResultNode
                {
                    Name = $"{decl.Name}[{arrayLen.Value}]",
                    TypeName = $"{resolvedType}[{arrayLen.Value}]",
                    StartOffset = _cursor,
                    ColorHex = colorHex,
                    Comment = comment,
                    IsExpanded = decl.Attributes?.IsOpen ?? false
                };

                for (int i = 0; i < arrayLen.Value && _cursor < _doc.Length; i++)
                {
                    var elemVal = InstantiateStruct(structDef, $"{decl.Name}[{i}]", colorHex, comment, out var elemNode);
                    arrVal.Elements.Add(elemVal);
                    arrNode.Children.Add(elemNode);
                }

                arrNode.ByteLength = _cursor - arrNode.StartOffset;
                arrNode.DisplayValue = $"struct {resolvedType}[{arrNode.Children.Count}]";
                arrVal.ByteSize = arrNode.ByteLength;
                SetVariable(decl.Name, arrVal);

                if (decl.Attributes?.IsHidden != true)
                    _nodeContainers.Peek().Add(arrNode);
            }
            else
            {
                var instVal = InstantiateStruct(structDef, decl.Name, colorHex, comment, out var structNode);
                SetVariable(decl.Name, instVal);
                if (decl.Attributes?.IsHidden != true)
                    _nodeContainers.Peek().Add(structNode);
            }
            return;
        }

        // Enum instance
        string? enumTypeName = null;
        if (_enumTypes.TryGetValue(resolvedType, out var enumDef))
        {
            enumTypeName = enumDef.EnumName;
            resolvedType = enumDef.UnderlyingType;
        }

        // char[] / uchar[] / byte[] arrays
        if (arrayLen.HasValue)
        {
            long start = _cursor;
            int elemSize = GetPrimitiveByteSize(resolvedType);
            long totalBytes = Math.Min((long)arrayLen.Value * elemSize, Math.Max(0, _doc.Length - start));

            if (IsCharType(resolvedType))
            {
                byte[] raw = _doc.ReadBytes(start, (int)totalBytes);
                _cursor += totalBytes;

                bool isAsciiChar = resolvedType.Equals("char", StringComparison.OrdinalIgnoreCase);
                string rawStr = isAsciiChar ? DecodeFixedAsciiString(raw) : FormatByteArrayOrString(resolvedType, raw);
                string displayStr = isAsciiChar ? $"\"{rawStr}\"" : rawStr;
                var val = BtValue.FromString(rawStr, start, totalBytes);
                for (int i = 0; i < raw.Length; i++)
                    val.Elements.Add(BtValue.FromInt(raw[i], start + i, 1));

                SetVariable(decl.Name, val);
                AddResultNode(
                    name: decl.Name,
                    typeName: $"{decl.TypeName}[{arrayLen.Value}]",
                    displayValue: displayStr,
                    offset: start,
                    length: totalBytes,
                    colorHex: colorHex,
                    comment: comment,
                    hidden: decl.Attributes?.IsHidden == true);
                return;
            }

            // General primitive array
            var listVal = new BtValue { StartOffset = start, ByteSize = totalBytes };
            var parentNode = new TemplateResultNode
            {
                Name = decl.Name,
                TypeName = $"{decl.TypeName}[{arrayLen.Value}]",
                StartOffset = start,
                ByteLength = totalBytes,
                ColorHex = colorHex,
                Comment = comment,
                IsExpanded = false
            };

            var previewSb = new StringBuilder("[ ");
            int maxChildren = Math.Min(arrayLen.Value, 64);
            for (int i = 0; i < arrayLen.Value && _cursor < _doc.Length; i++)
            {
                long elemStart = _cursor;
                var elemVal = ReadPrimitiveValue(resolvedType, hexFormat, enumTypeName, out string elemDisplay, out int consumed);
                listVal.Elements.Add(elemVal);

                if (i < 6)
                {
                    if (i > 0) previewSb.Append(", ");
                    previewSb.Append(elemDisplay);
                }
                if (i < maxChildren)
                {
                    parentNode.Children.Add(new TemplateResultNode
                    {
                        Name = $"{decl.Name}[{i}]",
                        TypeName = decl.TypeName,
                        DisplayValue = elemDisplay,
                        StartOffset = elemStart,
                        ByteLength = consumed,
                        ColorHex = colorHex
                    });
                }
            }
            if (arrayLen.Value > 6) previewSb.Append(", ...");
            previewSb.Append(" ]");
            parentNode.DisplayValue = previewSb.ToString();

            SetVariable(decl.Name, listVal);
            if (decl.Attributes?.IsHidden != true)
                _nodeContainers.Peek().Add(parentNode);
            RecordColorInterval(start, totalBytes, colorHex, decl.Name);
            return;
        }

        // Single primitive or null-terminated string field
        long fieldStart = _cursor;
        var fieldVal = ReadPrimitiveValue(resolvedType, hexFormat, enumTypeName, out string displayText, out int bytesRead);
        SetVariable(decl.Name, fieldVal);

        AddResultNode(
            name: decl.Attributes?.NameOverride ?? decl.Name,
            typeName: enumTypeName ?? decl.TypeName,
            displayValue: displayText,
            offset: fieldStart,
            length: bytesRead,
            colorHex: colorHex,
            comment: comment,
            hidden: decl.Attributes?.IsHidden == true);
    }

    private void ExecuteBitfieldDecl(BtVarDeclStmt decl, string resolvedType, int bitWidth, string colorHex, string comment)
    {
        int containerBytes = Math.Max(1, GetPrimitiveByteSize(resolvedType));
        if (_bitfieldBitsRemaining < bitWidth)
        {
            _bitfieldByteOffset = _cursor;
            var rawVal = ReadPrimitiveValue(resolvedType, hexFormat: true, enumTypeName: null, out _, out int consumed);
            _bitfieldCurrentValue = unchecked((ulong)rawVal.IntValue);
            _bitfieldBitsRemaining = consumed * 8;
        }

        ulong mask = bitWidth >= 64 ? ulong.MaxValue : ((1UL << bitWidth) - 1UL);
        long extracted = (long)(_bitfieldCurrentValue & mask);
        _bitfieldCurrentValue >>= bitWidth;
        _bitfieldBitsRemaining -= bitWidth;

        SetVariable(decl.Name, BtValue.FromInt(extracted, _bitfieldByteOffset, containerBytes));
        AddResultNode(
            name: $"{decl.Name} : {bitWidth}",
            typeName: $"{decl.TypeName} : {bitWidth}",
            displayValue: $"{extracted} (0x{extracted:X})",
            offset: _bitfieldByteOffset,
            length: containerBytes,
            colorHex: colorHex,
            comment: comment,
            hidden: decl.Attributes?.IsHidden == true);
    }

    private BtValue InstantiateStruct(
        BtStructDefStmt structDef,
        string instanceName,
        string inheritedColor,
        string inheritedComment,
        out TemplateResultNode structNode)
    {
        long startOffset = _cursor;
        string structColor = !string.IsNullOrEmpty(inheritedColor)
            ? inheritedColor
            : ResolveColorHex(structDef.Attributes);
        string structComment = !string.IsNullOrEmpty(inheritedComment)
            ? inheritedComment
            : ResolveComment(structDef.Attributes);

        structNode = new TemplateResultNode
        {
            Name = instanceName,
            TypeName = structDef.IsUnion ? $"union {structDef.TypeName}" : $"struct {structDef.TypeName}",
            StartOffset = startOffset,
            ColorHex = structColor,
            Comment = structComment,
            IsExpanded = true
        };

        var structScope = new Dictionary<string, BtValue>(StringComparer.Ordinal);
        _scopes.Push(structScope);
        _nodeContainers.Push(structNode.Children);

        string prevDefaultColor = _defaultBgColor;
        if (!string.IsNullOrEmpty(structColor))
            _defaultBgColor = structColor;

        long maxEndOffset = startOffset;
        try
        {
            foreach (var stmt in structDef.Body)
            {
                if (structDef.IsUnion)
                    _cursor = startOffset;

                ExecuteStmt(stmt);

                if (_cursor > maxEndOffset)
                    maxEndOffset = _cursor;
            }
        }
        finally
        {
            _defaultBgColor = prevDefaultColor;
            _nodeContainers.Pop();
            _scopes.Pop();
        }

        if (structDef.IsUnion)
            _cursor = maxEndOffset;

        long byteLen = Math.Max(0, _cursor - startOffset);
        structNode.ByteLength = byteLen;
        structNode.DisplayValue = $"{{ {structNode.Children.Count} fields, {byteLen} B }}";

        var val = new BtValue
        {
            StartOffset = startOffset,
            ByteSize = byteLen
        };
        foreach (var kvp in structScope)
        {
            val.Members[kvp.Key] = kvp.Value;
        }

        return val;
    }

    private BtValue ReadPrimitiveValue(
        string typeName,
        bool hexFormat,
        string? enumTypeName,
        out string displayText,
        out int bytesConsumed)
    {
        long offset = _cursor;
        long remaining = Math.Max(0, _doc.Length - offset);
        string lower = typeName.ToLowerInvariant();

        if (lower == "string")
        {
            var sb = new StringBuilder();
            int len = 0;
            while (offset + len < _doc.Length && len < 4096)
            {
                byte b = _doc.ReadByte(offset + len);
                len++;
                if (b == 0) break;
                if (b >= 32 && b < 127) sb.Append((char)b);
                else sb.Append($"\\x{b:X2}");
            }
            _cursor += len;
            bytesConsumed = len;
            displayText = $"\"{sb}\"";
            return BtValue.FromString(sb.ToString(), offset, len);
        }

        int size = GetPrimitiveByteSize(lower);
        bytesConsumed = (int)Math.Min(size, remaining);
        Span<byte> buf = stackalloc byte[8];
        buf.Clear();
        if (bytesConsumed > 0)
            _doc.ReadBytes(offset, buf[..bytesConsumed]);
        _cursor += bytesConsumed;

        switch (lower)
        {
            case "char":
            case "sbyte":
            {
                sbyte v = unchecked((sbyte)buf[0]);
                char ch = buf[0] is >= 32 and < 127 ? (char)buf[0] : '.';
                displayText = FormatWithEnum(v, $"'{ch}' ({v}, 0x{buf[0]:X2})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "uchar":
            case "byte":
            case "ubyte":
            {
                byte v = buf[0];
                displayText = FormatWithEnum(v, hexFormat ? $"0x{v:X2} ({v})" : $"{v} (0x{v:X2})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "short":
            case "int16":
            {
                short v = _bigEndian ? BinaryPrimitives.ReadInt16BigEndian(buf[..2]) : BinaryPrimitives.ReadInt16LittleEndian(buf[..2]);
                displayText = FormatWithEnum(v, hexFormat ? $"0x{(ushort)v:X4} ({v})" : $"{v} (0x{(ushort)v:X4})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "ushort":
            case "uint16":
            case "word":
            {
                ushort v = _bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(buf[..2]) : BinaryPrimitives.ReadUInt16LittleEndian(buf[..2]);
                displayText = FormatWithEnum(v, hexFormat ? $"0x{v:X4} ({v})" : $"{v} (0x{v:X4})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "dosdate":
            {
                ushort v = _bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(buf[..2]) : BinaryPrimitives.ReadUInt16LittleEndian(buf[..2]);
                displayText = $"{DataInspectorDecoder.DecodeDosDate(v)} (0x{v:X4})";
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "dostime":
            {
                ushort v = _bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(buf[..2]) : BinaryPrimitives.ReadUInt16LittleEndian(buf[..2]);
                displayText = $"{DataInspectorDecoder.DecodeDosTime(v)} (0x{v:X4})";
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "int":
            case "long":
            case "int32":
            {
                int v = _bigEndian ? BinaryPrimitives.ReadInt32BigEndian(buf[..4]) : BinaryPrimitives.ReadInt32LittleEndian(buf[..4]);
                displayText = FormatWithEnum(v, hexFormat ? $"0x{(uint)v:X8} ({v})" : $"{v} (0x{(uint)v:X8})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "uint":
            case "ulong":
            case "uint32":
            case "dword":
            {
                uint v = _bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(buf[..4]) : BinaryPrimitives.ReadUInt32LittleEndian(buf[..4]);
                displayText = FormatWithEnum(v, hexFormat ? $"0x{v:X8} ({v})" : $"{v} (0x{v:X8})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "time_t":
            {
                uint v = _bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(buf[..4]) : BinaryPrimitives.ReadUInt32LittleEndian(buf[..4]);
                string dt = DateTimeOffset.FromUnixTimeSeconds(v).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
                displayText = $"{dt} ({v})";
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "float":
            {
                float v = _bigEndian ? BinaryPrimitives.ReadSingleBigEndian(buf[..4]) : BinaryPrimitives.ReadSingleLittleEndian(buf[..4]);
                displayText = v.ToString("G7", CultureInfo.InvariantCulture);
                return BtValue.FromFloat(v, offset, bytesConsumed);
            }

            case "double":
            {
                double v = _bigEndian ? BinaryPrimitives.ReadDoubleBigEndian(buf[..8]) : BinaryPrimitives.ReadDoubleLittleEndian(buf[..8]);
                displayText = v.ToString("G15", CultureInfo.InvariantCulture);
                return BtValue.FromFloat(v, offset, bytesConsumed);
            }

            case "int64":
            case "quad":
            case "__int64":
            case "time64_t":
            case "filetime":
            {
                long v = _bigEndian ? BinaryPrimitives.ReadInt64BigEndian(buf[..8]) : BinaryPrimitives.ReadInt64LittleEndian(buf[..8]);
                displayText = FormatWithEnum(v, $"0x{(ulong)v:X16} ({v})", enumTypeName);
                return BtValue.FromInt(v, offset, bytesConsumed);
            }

            case "uint64":
            case "uquad":
            case "qword":
            {
                ulong v = _bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(buf[..8]) : BinaryPrimitives.ReadUInt64LittleEndian(buf[..8]);
                long signed = unchecked((long)v);
                displayText = FormatWithEnum(signed, $"0x{v:X16} ({v})", enumTypeName);
                return BtValue.FromInt(signed, offset, bytesConsumed);
            }

            default:
            {
                uint v = _bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(buf[..4]) : BinaryPrimitives.ReadUInt32LittleEndian(buf[..4]);
                displayText = $"{v} (0x{v:X8})";
                return BtValue.FromInt(v, offset, bytesConsumed);
            }
        }
    }

    private string FormatWithEnum(long value, string baseDisplay, string? enumTypeName)
    {
        if (enumTypeName is not null &&
            _enumValueNames.TryGetValue(enumTypeName, out var map) &&
            map.TryGetValue(value, out string? enumMember))
        {
            return $"{enumMember} ({baseDisplay})";
        }
        return baseDisplay;
    }

    // Expression evaluation
    private BtValue EvaluateExpr(BtExpr expr)
    {
        switch (expr)
        {
            case BtIntLiteralExpr i:
                return BtValue.FromInt(i.Value);

            case BtFloatLiteralExpr f:
                return BtValue.FromFloat(f.Value);

            case BtStringLiteralExpr s:
                return BtValue.FromString(s.Value);

            case BtIdentifierExpr id:
                return LookupVariable(id.Name);

            case BtSizeofExpr sz:
                if (_scopes.Any(sc => sc.TryGetValue(sz.TypeOrVarName, out _)))
                {
                    var v = LookupVariable(sz.TypeOrVarName);
                    return BtValue.FromInt(v.ByteSize > 0 ? v.ByteSize : 4);
                }
                return BtValue.FromInt(GetPrimitiveByteSize(sz.TypeOrVarName));

            case BtMemberAccessExpr mem:
            {
                var target = EvaluateExpr(mem.Target);
                if (target.Members.TryGetValue(mem.MemberName, out var mVal))
                    return mVal;
                return BtValue.FromInt(0);
            }

            case BtIndexExpr idx:
            {
                var target = EvaluateExpr(idx.Target);
                int index = (int)EvaluateExpr(idx.Index).IntValue;
                if (index >= 0 && index < target.Elements.Count)
                    return target.Elements[index];
                if (target.IsString && index >= 0 && index < target.StringValue!.Length)
                    return BtValue.FromInt(target.StringValue[index]);
                return BtValue.FromInt(0);
            }

            case BtUnaryExpr un:
            {
                if (un.Operator is "++" or "--")
                {
                    var current = EvaluateExpr(un.Operand);
                    long delta = un.Operator == "++" ? 1 : -1;
                    var updated = BtValue.FromInt(current.IntValue + delta);
                    AssignToTarget(un.Operand, updated);
                    return un.IsPostfix ? current : updated;
                }

                var val = EvaluateExpr(un.Operand);
                return un.Operator switch
                {
                    "-" => val.IsFloat ? BtValue.FromFloat(-val.FloatValue) : BtValue.FromInt(-val.IntValue),
                    "+" => val,
                    "!" => BtValue.FromInt(val.IsTruthy ? 0 : 1),
                    "~" => BtValue.FromInt(~val.IntValue),
                    _ => val
                };
            }

            case BtAssignExpr assign:
            {
                var rhs = EvaluateExpr(assign.Value);
                if (assign.Operator == "=")
                {
                    AssignToTarget(assign.Target, rhs);
                    return rhs;
                }

                var lhs = EvaluateExpr(assign.Target);
                string binOp = assign.Operator[..^1];
                var combined = ApplyBinaryOp(binOp, lhs, rhs);
                AssignToTarget(assign.Target, combined);
                return combined;
            }

            case BtTernaryExpr tern:
                return EvaluateExpr(tern.Condition).IsTruthy
                    ? EvaluateExpr(tern.TrueExpr)
                    : EvaluateExpr(tern.FalseExpr);

            case BtBinaryExpr bin:
            {
                if (bin.Operator == "&&")
                    return BtValue.FromInt(EvaluateExpr(bin.Left).IsTruthy && EvaluateExpr(bin.Right).IsTruthy ? 1 : 0);
                if (bin.Operator == "||")
                    return BtValue.FromInt(EvaluateExpr(bin.Left).IsTruthy || EvaluateExpr(bin.Right).IsTruthy ? 1 : 0);

                var left = EvaluateExpr(bin.Left);
                var right = EvaluateExpr(bin.Right);
                return ApplyBinaryOp(bin.Operator, left, right);
            }

            case BtCallExpr call:
                return InvokeFunction(call);

            default:
                return BtValue.FromInt(0);
        }
    }

    private BtValue ApplyBinaryOp(string op, BtValue left, BtValue right)
    {
        if (left.IsString || right.IsString)
        {
            string ls = left.ToString();
            string rs = right.ToString();
            return op switch
            {
                "+" => BtValue.FromString(ls + rs),
                "==" => BtValue.FromInt(string.Equals(ls, rs, StringComparison.Ordinal) ? 1 : 0),
                "!=" => BtValue.FromInt(!string.Equals(ls, rs, StringComparison.Ordinal) ? 1 : 0),
                _ => BtValue.FromInt(0)
            };
        }

        if (left.IsFloat || right.IsFloat)
        {
            double ld = left.IsFloat ? left.FloatValue : left.IntValue;
            double rd = right.IsFloat ? right.FloatValue : right.IntValue;
            return op switch
            {
                "+" => BtValue.FromFloat(ld + rd),
                "-" => BtValue.FromFloat(ld - rd),
                "*" => BtValue.FromFloat(ld * rd),
                "/" => BtValue.FromFloat(Math.Abs(rd) > 1e-15 ? ld / rd : 0.0),
                "==" => BtValue.FromInt(Math.Abs(ld - rd) < 1e-9 ? 1 : 0),
                "!=" => BtValue.FromInt(Math.Abs(ld - rd) >= 1e-9 ? 1 : 0),
                "<" => BtValue.FromInt(ld < rd ? 1 : 0),
                "<=" => BtValue.FromInt(ld <= rd ? 1 : 0),
                ">" => BtValue.FromInt(ld > rd ? 1 : 0),
                ">=" => BtValue.FromInt(ld >= rd ? 1 : 0),
                _ => BtValue.FromFloat(0)
            };
        }

        long l = left.IntValue;
        long r = right.IntValue;
        return op switch
        {
            "+" => BtValue.FromInt(l + r),
            "-" => BtValue.FromInt(l - r),
            "*" => BtValue.FromInt(l * r),
            "/" => BtValue.FromInt(r != 0 ? l / r : 0),
            "%" => BtValue.FromInt(r != 0 ? l % r : 0),
            "&" => BtValue.FromInt(l & r),
            "|" => BtValue.FromInt(l | r),
            "^" => BtValue.FromInt(l ^ r),
            "<<" => BtValue.FromInt(l << (int)(r & 63)),
            ">>" => BtValue.FromInt(l >> (int)(r & 63)),
            "==" => BtValue.FromInt(l == r ? 1 : 0),
            "!=" => BtValue.FromInt(l != r ? 1 : 0),
            "<" => BtValue.FromInt(l < r ? 1 : 0),
            "<=" => BtValue.FromInt(l <= r ? 1 : 0),
            ">" => BtValue.FromInt(l > r ? 1 : 0),
            ">=" => BtValue.FromInt(l >= r ? 1 : 0),
            _ => BtValue.FromInt(0)
        };
    }

    private BtValue InvokeFunction(BtCallExpr call)
    {
        var args = call.Arguments.Select(EvaluateExpr).ToList();
        string fn = call.FunctionName;

        switch (fn)
        {
            case "LittleEndian":
                _bigEndian = false;
                return BtValue.FromInt(0);

            case "BigEndian":
                _bigEndian = true;
                return BtValue.FromInt(0);

            case "IsBigEndian":
                return BtValue.FromInt(_bigEndian ? 1 : 0);

            case "FTell":
                return BtValue.FromInt(_cursor);

            case "FSeek":
            {
                long pos = args.Count > 0 ? args[0].IntValue : 0;
                _cursor = Math.Clamp(pos, 0, _doc.Length);
                return BtValue.FromInt(0);
            }

            case "FSkip":
            {
                long delta = args.Count > 0 ? args[0].IntValue : 0;
                _cursor = Math.Clamp(_cursor + delta, 0, _doc.Length);
                return BtValue.FromInt(0);
            }

            case "FEof":
                return BtValue.FromInt(_cursor >= _doc.Length ? 1 : 0);

            case "FileSize":
                return BtValue.FromInt(_doc.Length);

            case "SetBackColor":
            {
                if (args.Count > 0)
                    _defaultBgColor = BgrIntToHexColor(args[0].IntValue);
                return BtValue.FromInt(0);
            }

            case "SetForeColor":
            case "SetColor":
            case "BitfieldDisablePadding":
            case "BitfieldRightToLeft":
            case "BitfieldLeftToRight":
                return BtValue.FromInt(0);

            case "ReadByte":
            case "ReadUByte":
            {
                long pos = args.Count > 0 ? args[0].IntValue : _cursor;
                if (pos < 0 || pos >= _doc.Length) return BtValue.FromInt(0);
                byte b = _doc.ReadByte(pos);
                return BtValue.FromInt(fn == "ReadByte" ? unchecked((sbyte)b) : b);
            }

            case "ReadShort":
            case "ReadUShort":
            {
                long pos = args.Count > 0 ? args[0].IntValue : _cursor;
                if (pos < 0 || pos + 2 > _doc.Length) return BtValue.FromInt(0);
                Span<byte> b = stackalloc byte[2];
                _doc.ReadBytes(pos, b);
                if (fn == "ReadShort")
                    return BtValue.FromInt(_bigEndian ? BinaryPrimitives.ReadInt16BigEndian(b) : BinaryPrimitives.ReadInt16LittleEndian(b));
                return BtValue.FromInt(_bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b));
            }

            case "ReadInt":
            case "ReadUInt":
            {
                long pos = args.Count > 0 ? args[0].IntValue : _cursor;
                if (pos < 0 || pos + 4 > _doc.Length) return BtValue.FromInt(0);
                Span<byte> b = stackalloc byte[4];
                _doc.ReadBytes(pos, b);
                if (fn == "ReadInt")
                    return BtValue.FromInt(_bigEndian ? BinaryPrimitives.ReadInt32BigEndian(b) : BinaryPrimitives.ReadInt32LittleEndian(b));
                return BtValue.FromInt(_bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b));
            }

            case "ReadInt64":
            case "ReadUInt64":
            case "ReadQuad":
            {
                long pos = args.Count > 0 ? args[0].IntValue : _cursor;
                if (pos < 0 || pos + 8 > _doc.Length) return BtValue.FromInt(0);
                Span<byte> b = stackalloc byte[8];
                _doc.ReadBytes(pos, b);
                return BtValue.FromInt(_bigEndian ? BinaryPrimitives.ReadInt64BigEndian(b) : BinaryPrimitives.ReadInt64LittleEndian(b));
            }

            case "ReadString":
            {
                long pos = args.Count > 0 ? args[0].IntValue : _cursor;
                int maxLen = args.Count > 1 && args[1].IntValue > 0 ? (int)args[1].IntValue : 256;
                if (pos < 0 || pos >= _doc.Length) return BtValue.FromString("");
                byte[] bytes = _doc.ReadBytes(pos, maxLen);
                int nul = Array.IndexOf(bytes, (byte)0);
                int count = nul >= 0 ? nul : bytes.Length;
                return BtValue.FromString(Encoding.ASCII.GetString(bytes, 0, count));
            }

            case "Printf":
            case "Warning":
            case "SPrintf":
            {
                string formatted = FormatPrintf(args);
                if (fn != "SPrintf")
                    _consoleOutput.Add(formatted.TrimEnd('\r', '\n'));
                return BtValue.FromString(formatted);
            }

            case "Strcmp":
            case "Stricmp":
            {
                string a = args.Count > 0 ? args[0].ToString() : "";
                string b = args.Count > 1 ? args[1].ToString() : "";
                var cmp = fn == "Stricmp" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                return BtValue.FromInt(string.Compare(a, b, cmp));
            }

            case "Memcmp":
            {
                string a = args.Count > 0 ? args[0].ToString() : "";
                string b = args.Count > 1 ? args[1].ToString() : "";
                int n = args.Count > 2 ? (int)args[2].IntValue : Math.Min(a.Length, b.Length);
                string sa = a.Length > n ? a[..n] : a;
                string sb = b.Length > n ? b[..n] : b;
                return BtValue.FromInt(string.CompareOrdinal(sa, sb));
            }

            case "Strlen":
                return BtValue.FromInt(args.Count > 0 ? args[0].ToString().Length : 0);

            case "Min":
                return BtValue.FromInt(args.Count >= 2 ? Math.Min(args[0].IntValue, args[1].IntValue) : 0);

            case "Max":
                return BtValue.FromInt(args.Count >= 2 ? Math.Max(args[0].IntValue, args[1].IntValue) : 0);

            case "Abs":
                return BtValue.FromInt(args.Count >= 1 ? Math.Abs(args[0].IntValue) : 0);
        }

        // User-defined function
        if (_functions.TryGetValue(fn, out var userFunc))
        {
            var fnScope = new Dictionary<string, BtValue>(StringComparer.Ordinal);
            for (int i = 0; i < userFunc.Parameters.Count; i++)
            {
                fnScope[userFunc.Parameters[i].Name] = i < args.Count ? args[i] : BtValue.FromInt(0);
            }

            _scopes.Push(fnScope);
            try
            {
                ExecuteStmt(userFunc.Body);
            }
            catch (ReturnException ret)
            {
                return ret.Value;
            }
            finally
            {
                _scopes.Pop();
            }
        }

        return BtValue.FromInt(0);
    }

    private static string FormatPrintf(List<BtValue> args)
    {
        if (args.Count == 0) return "";
        string fmt = args[0].ToString();
        if (args.Count == 1) return fmt;

        var sb = new StringBuilder();
        int argIdx = 1;
        for (int i = 0; i < fmt.Length; i++)
        {
            if (fmt[i] == '%' && i + 1 < fmt.Length)
            {
                i++;
                // Skip width/precision/flags like 08X, lX, etc.
                bool zeroPad = false;
                int width = 0;
                if (fmt[i] == '0')
                {
                    zeroPad = true;
                    i++;
                }
                while (i < fmt.Length && char.IsDigit(fmt[i]))
                {
                    width = width * 10 + (fmt[i] - '0');
                    i++;
                }
                while (i < fmt.Length && (fmt[i] is 'l' or 'L' or 'h'))
                    i++;

                if (i >= fmt.Length) break;
                char spec = fmt[i];
                if (spec == '%')
                {
                    sb.Append('%');
                    continue;
                }

                var arg = argIdx < args.Count ? args[argIdx++] : BtValue.FromInt(0);
                string formatted = spec switch
                {
                    'x' => arg.IntValue.ToString(zeroPad && width > 0 ? $"x{width}" : "x"),
                    'X' => arg.IntValue.ToString(zeroPad && width > 0 ? $"X{width}" : "X"),
                    'd' or 'i' or 'u' => arg.IntValue.ToString(zeroPad && width > 0 ? $"D{width}" : "D"),
                    'f' or 'g' => (arg.IsFloat ? arg.FloatValue : arg.IntValue).ToString("G", CultureInfo.InvariantCulture),
                    'c' => ((char)(arg.IntValue & 0xFF)).ToString(),
                    's' => arg.ToString(),
                    _ => arg.ToString()
                };
                sb.Append(formatted);
            }
            else
            {
                sb.Append(fmt[i]);
            }
        }
        return sb.ToString();
    }

    private BtValue LookupVariable(string name)
    {
        foreach (var scope in _scopes)
        {
            if (scope.TryGetValue(name, out var val))
                return val;
        }
        return BtValue.FromInt(0);
    }

    private void SetVariable(string name, BtValue value)
    {
        _scopes.Peek()[name] = value;
    }

    private void AssignToTarget(BtExpr target, BtValue value)
    {
        if (target is BtIdentifierExpr id)
        {
            foreach (var scope in _scopes)
            {
                if (scope.ContainsKey(id.Name))
                {
                    scope[id.Name] = value;
                    return;
                }
            }
            _scopes.Peek()[id.Name] = value;
        }
        else if (target is BtMemberAccessExpr mem)
        {
            var obj = EvaluateExpr(mem.Target);
            obj.Members[mem.MemberName] = value;
        }
    }

    private void AddResultNode(
        string name,
        string typeName,
        string displayValue,
        long offset,
        long length,
        string colorHex,
        string comment,
        bool hidden)
    {
        if (!hidden)
        {
            _nodeContainers.Peek().Add(new TemplateResultNode
            {
                Name = name,
                TypeName = typeName,
                DisplayValue = displayValue,
                StartOffset = offset,
                ByteLength = length,
                ColorHex = colorHex,
                Comment = comment
            });
        }

        RecordColorInterval(offset, length, colorHex, name);
    }

    private void RecordColorInterval(long offset, long length, string colorHex, string label)
    {
        if (length > 0 && !string.IsNullOrEmpty(colorHex))
        {
            _colorIntervals.Add(new ByteColorInterval(offset, length, colorHex, label));
        }
    }

    private string ResolveColorHex(BtFieldAttributes? attrs)
    {
        if (attrs?.BgColor is not null)
        {
            if (attrs.BgColor is BtIdentifierExpr id && ColorConstants.TryGetValue(id.Name, out var c))
                return c.HexColor;

            long bgr = EvaluateExpr(attrs.BgColor).IntValue;
            return BgrIntToHexColor(bgr);
        }
        return _defaultBgColor;
    }

    private string ResolveComment(BtFieldAttributes? attrs)
    {
        if (attrs?.Comment is not null)
            return EvaluateExpr(attrs.Comment).ToString();
        return "";
    }

    private static string BgrIntToHexColor(long bgr)
    {
        if (bgr < 0) return "";
        int b = (int)((bgr >> 16) & 0xFF);
        int g = (int)((bgr >> 8) & 0xFF);
        int r = (int)(bgr & 0xFF);
        return $"#{r:X2}{g:X2}{b:X2}";
    }

    private static bool IsCharType(string typeName)
    {
        return typeName.Equals("char", StringComparison.OrdinalIgnoreCase) ||
               typeName.Equals("uchar", StringComparison.OrdinalIgnoreCase) ||
               typeName.Equals("byte", StringComparison.OrdinalIgnoreCase) ||
               typeName.Equals("ubyte", StringComparison.OrdinalIgnoreCase);
    }

    private static string DecodeFixedAsciiString(byte[] raw)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < raw.Length; i++)
        {
            byte b = raw[i];
            if (b == 0) break;
            if (b >= 32 && b < 127) sb.Append((char)b);
            else sb.Append($"\\x{b:X2}");
        }
        return sb.ToString();
    }

    private static string FormatByteArrayOrString(string typeName, byte[] raw)
    {
        if (typeName.Equals("char", StringComparison.OrdinalIgnoreCase))
        {
            return $"\"{DecodeFixedAsciiString(raw)}\"";
        }

        int previewLen = Math.Min(raw.Length, 16);
        var hex = new StringBuilder();
        for (int i = 0; i < previewLen; i++)
        {
            if (i > 0) hex.Append(' ');
            hex.Append(raw[i].ToString("X2"));
        }
        if (raw.Length > previewLen)
            hex.Append($" ... ({raw.Length} bytes)");
        return hex.ToString();
    }

    private static int GetPrimitiveByteSize(string typeName)
    {
        return typeName.ToLowerInvariant() switch
        {
            "char" or "uchar" or "byte" or "sbyte" or "ubyte" => 1,
            "short" or "ushort" or "int16" or "uint16" or "word" or "dosdate" or "dostime" or "hfloat" => 2,
            "int" or "uint" or "long" or "ulong" or "int32" or "uint32" or "dword" or "float" or "time_t" => 4,
            "int64" or "uint64" or "quad" or "uquad" or "qword" or "__int64" or "double" or "filetime" or "oletime" or "time64_t" => 8,
            _ => 4
        };
    }
}
