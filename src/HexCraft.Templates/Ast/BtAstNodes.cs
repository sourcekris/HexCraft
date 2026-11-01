using System.Collections.Generic;

namespace HexCraft.Templates.Ast;

/// <summary>
/// Represents 010 Editor field attributes such as &lt;bgcolor=cLtBlue, fgcolor=cWhite, format=hex, comment="Header"&gt;.
/// </summary>
public sealed record BtFieldAttributes(
    BtExpr? BgColor = null,
    BtExpr? FgColor = null,
    string? Format = null,
    BtExpr? Comment = null,
    string? NameOverride = null,
    bool IsHidden = false,
    bool IsOpen = false);

public abstract record BtNode(int Line);

public sealed record BtProgram(IReadOnlyList<BtStmt> Statements) : BtNode(1);

// Statements
public abstract record BtStmt(int Line) : BtNode(Line);

public sealed record BtBlockStmt(IReadOnlyList<BtStmt> Statements, int Line) : BtStmt(Line);

public sealed record BtExprStmt(BtExpr Expression, int Line) : BtStmt(Line);

public sealed record BtIfStmt(
    BtExpr Condition,
    BtStmt ThenBranch,
    BtStmt? ElseBranch,
    int Line) : BtStmt(Line);

public sealed record BtWhileStmt(
    BtExpr Condition,
    BtStmt Body,
    int Line) : BtStmt(Line);

public sealed record BtDoWhileStmt(
    BtStmt Body,
    BtExpr Condition,
    int Line) : BtStmt(Line);

public sealed record BtForStmt(
    BtStmt? Initializer,
    BtExpr? Condition,
    BtExpr? Increment,
    BtStmt Body,
    int Line) : BtStmt(Line);

public sealed record BtSwitchCase(
    BtExpr? MatchValue, // null for 'default:'
    IReadOnlyList<BtStmt> Statements);

public sealed record BtSwitchStmt(
    BtExpr Value,
    IReadOnlyList<BtSwitchCase> Cases,
    int Line) : BtStmt(Line);

public sealed record BtBreakStmt(int Line) : BtStmt(Line);
public sealed record BtContinueStmt(int Line) : BtStmt(Line);
public sealed record BtReturnStmt(BtExpr? Value, int Line) : BtStmt(Line);

/// <summary>
/// A variable or template field declaration, e.g.:
///   uint32 width &lt;bgcolor=cLtGreen, comment="Image width"&gt;;
///   uchar chunkData[length];
///   local int i = 0;
///   uint flags : 4;
/// </summary>
public sealed record BtVarDeclStmt(
    bool IsLocal,
    string TypeName,
    string Name,
    BtExpr? ArrayLength,
    int? BitfieldWidth,
    BtExpr? Initializer,
    BtFieldAttributes? Attributes,
    int Line) : BtStmt(Line);

public sealed record BtStructDefStmt(
    bool IsUnion,
    string TypeName,
    IReadOnlyList<string> Parameters,
    IReadOnlyList<BtStmt> Body,
    string? InstanceName,
    BtExpr? InstanceArrayLength,
    BtFieldAttributes? Attributes,
    int Line) : BtStmt(Line);

public sealed record BtEnumMember(string Name, BtExpr? ValueExpr);

public sealed record BtEnumDefStmt(
    string UnderlyingType,
    string EnumName,
    IReadOnlyList<BtEnumMember> Members,
    string? InstanceName,
    BtFieldAttributes? Attributes,
    int Line) : BtStmt(Line);

public sealed record BtTypedefStmt(
    string ExistingType,
    string AliasName,
    int? FixedArraySize,
    int Line) : BtStmt(Line);

public sealed record BtFunctionParameter(string TypeName, string Name);

public sealed record BtFunctionDefStmt(
    string ReturnType,
    string Name,
    IReadOnlyList<BtFunctionParameter> Parameters,
    BtBlockStmt Body,
    int Line) : BtStmt(Line);

// Expressions
public abstract record BtExpr(int Line) : BtNode(Line);

public sealed record BtIntLiteralExpr(long Value, string RawLexeme, int Line) : BtExpr(Line);
public sealed record BtFloatLiteralExpr(double Value, int Line) : BtExpr(Line);
public sealed record BtStringLiteralExpr(string Value, int Line) : BtExpr(Line);
public sealed record BtIdentifierExpr(string Name, int Line) : BtExpr(Line);

public sealed record BtUnaryExpr(string Operator, BtExpr Operand, bool IsPostfix, int Line) : BtExpr(Line);
public sealed record BtBinaryExpr(string Operator, BtExpr Left, BtExpr Right, int Line) : BtExpr(Line);
public sealed record BtTernaryExpr(BtExpr Condition, BtExpr TrueExpr, BtExpr FalseExpr, int Line) : BtExpr(Line);
public sealed record BtAssignExpr(string Operator, BtExpr Target, BtExpr Value, int Line) : BtExpr(Line);

public sealed record BtMemberAccessExpr(BtExpr Target, string MemberName, int Line) : BtExpr(Line);
public sealed record BtIndexExpr(BtExpr Target, BtExpr Index, int Line) : BtExpr(Line);
public sealed record BtCallExpr(string FunctionName, IReadOnlyList<BtExpr> Arguments, int Line) : BtExpr(Line);
public sealed record BtSizeofExpr(string TypeOrVarName, int Line) : BtExpr(Line);

