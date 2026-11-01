using System;
using System.Collections.Generic;
using HexCraft.Templates.Ast;
using HexCraft.Templates.Lexing;

namespace HexCraft.Templates.Parsing;

/// <summary>
/// Recursive-descent parser for 010 Editor Binary Templates (.bt).
/// Handles primitive types, structs/unions, enums, typedefs, bitfields, dynamic arrays,
/// local variables, control flow statements, functions, and &lt;...&gt; field attributes.
/// </summary>
public sealed class BtParser
{
    private readonly List<BtToken> _tokens;
    private int _pos;

    private static readonly HashSet<string> BuiltinTypeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "char", "uchar", "byte", "sbyte", "ubyte",
        "short", "ushort", "int16", "uint16", "WORD",
        "int", "uint", "long", "ulong", "int32", "uint32", "DWORD",
        "int64", "uint64", "quad", "uquad", "QWORD", "__int64",
        "float", "double", "hfloat",
        "dosdate", "dostime", "time_t", "time64_t", "FILETIME", "OLETIME",
        "string", "wstring", "void"
    };

    private readonly HashSet<string> _userTypes = new(StringComparer.Ordinal);

    public BtParser(List<BtToken> tokens)
    {
        _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
    }

    public static BtProgram Parse(string source)
    {
        var tokens = BtLexer.Tokenize(source);
        var parser = new BtParser(tokens);
        return parser.ParseProgram();
    }

    public BtProgram ParseProgram()
    {
        var statements = new List<BtStmt>();
        while (!IsAtEnd())
        {
            if (Match(BtTokenKind.Semicolon))
                continue;
            statements.Add(ParseStatement());
        }
        return new BtProgram(statements);
    }

    private BtStmt ParseStatement()
    {
        var tok = Peek();

        if (Match(BtTokenKind.LBrace))
            return ParseBlock(tok.Line);

        if (Match(BtTokenKind.If))
            return ParseIf(tok.Line);

        if (Match(BtTokenKind.While))
            return ParseWhile(tok.Line);

        if (Match(BtTokenKind.Do))
            return ParseDoWhile(tok.Line);

        if (Match(BtTokenKind.For))
            return ParseFor(tok.Line);

        if (Match(BtTokenKind.Switch))
            return ParseSwitch(tok.Line);

        if (Match(BtTokenKind.Break))
        {
            ConsumeOptional(BtTokenKind.Semicolon);
            return new BtBreakStmt(tok.Line);
        }

        if (Match(BtTokenKind.Continue))
        {
            ConsumeOptional(BtTokenKind.Semicolon);
            return new BtContinueStmt(tok.Line);
        }

        if (Match(BtTokenKind.Return))
        {
            BtExpr? val = null;
            if (!Check(BtTokenKind.Semicolon))
                val = ParseExpression();
            ConsumeOptional(BtTokenKind.Semicolon);
            return new BtReturnStmt(val, tok.Line);
        }

        if (Match(BtTokenKind.Typedef))
            return ParseTypedef(tok.Line);

        if (Check(BtTokenKind.Struct) || Check(BtTokenKind.Union))
            return ParseStructOrUnion();

        if (Check(BtTokenKind.Enum))
            return ParseEnum();

        if (Match(BtTokenKind.Local))
        {
            ConsumeOptional(BtTokenKind.Const);
            string typeName = ParseTypeName();
            return ParseVarDeclarationAfterType(isLocal: true, typeName, tok.Line);
        }

        if (Match(BtTokenKind.Const))
        {
            bool isLocal = Match(BtTokenKind.Local) || true; // treat top-level const as local constant
            string typeName = ParseTypeName();
            return ParseVarDeclarationAfterType(isLocal: isLocal, typeName, tok.Line);
        }

        if (IsStartOfDeclaration())
        {
            string typeName = ParseTypeName();
            // Check if this is a function definition: Type Name ( ... ) { ... }
            if (Check(BtTokenKind.Identifier) && Peek(1).Kind == BtTokenKind.LParen)
            {
                // Look ahead past matching ')' to see if '{' follows
                if (IsFunctionDefinitionLookahead())
                {
                    return ParseFunctionDef(typeName, tok.Line);
                }
            }
            return ParseVarDeclarationAfterType(isLocal: false, typeName, tok.Line);
        }

        var expr = ParseExpression();
        ConsumeOptional(BtTokenKind.Semicolon);
        return new BtExprStmt(expr, tok.Line);
    }

    private BtBlockStmt ParseBlock(int line)
    {
        var stmts = new List<BtStmt>();
        while (!IsAtEnd() && !Check(BtTokenKind.RBrace))
        {
            if (Match(BtTokenKind.Semicolon))
                continue;
            stmts.Add(ParseStatement());
        }
        Consume(BtTokenKind.RBrace, "Expected '}' after block.");
        return new BtBlockStmt(stmts, line);
    }

    private BtIfStmt ParseIf(int line)
    {
        Consume(BtTokenKind.LParen, "Expected '(' after 'if'.");
        var cond = ParseExpression();
        Consume(BtTokenKind.RParen, "Expected ')' after if condition.");
        var thenBranch = ParseStatement();
        BtStmt? elseBranch = null;
        if (Match(BtTokenKind.Else))
            elseBranch = ParseStatement();
        return new BtIfStmt(cond, thenBranch, elseBranch, line);
    }

    private BtWhileStmt ParseWhile(int line)
    {
        Consume(BtTokenKind.LParen, "Expected '(' after 'while'.");
        var cond = ParseExpression();
        Consume(BtTokenKind.RParen, "Expected ')' after while condition.");
        var body = ParseStatement();
        return new BtWhileStmt(cond, body, line);
    }

    private BtDoWhileStmt ParseDoWhile(int line)
    {
        var body = ParseStatement();
        Consume(BtTokenKind.While, "Expected 'while' after do body.");
        Consume(BtTokenKind.LParen, "Expected '(' after 'while'.");
        var cond = ParseExpression();
        Consume(BtTokenKind.RParen, "Expected ')' after do-while condition.");
        ConsumeOptional(BtTokenKind.Semicolon);
        return new BtDoWhileStmt(body, cond, line);
    }

    private BtForStmt ParseFor(int line)
    {
        Consume(BtTokenKind.LParen, "Expected '(' after 'for'.");
        BtStmt? init = null;
        if (!Match(BtTokenKind.Semicolon))
        {
            if (Match(BtTokenKind.Local))
            {
                string tName = ParseTypeName();
                init = ParseVarDeclarationAfterType(isLocal: true, tName, Peek().Line);
            }
            else if (IsStartOfDeclaration())
            {
                string tName = ParseTypeName();
                init = ParseVarDeclarationAfterType(isLocal: true, tName, Peek().Line);
            }
            else
            {
                var initExpr = ParseExpression();
                ConsumeOptional(BtTokenKind.Semicolon);
                init = new BtExprStmt(initExpr, line);
            }
        }

        BtExpr? cond = null;
        if (!Check(BtTokenKind.Semicolon))
            cond = ParseExpression();
        ConsumeOptional(BtTokenKind.Semicolon);

        BtExpr? inc = null;
        if (!Check(BtTokenKind.RParen))
            inc = ParseExpression();
        Consume(BtTokenKind.RParen, "Expected ')' after for clauses.");

        var body = ParseStatement();
        return new BtForStmt(init, cond, inc, body, line);
    }

    private BtSwitchStmt ParseSwitch(int line)
    {
        Consume(BtTokenKind.LParen, "Expected '(' after 'switch'.");
        var val = ParseExpression();
        Consume(BtTokenKind.RParen, "Expected ')' after switch value.");
        Consume(BtTokenKind.LBrace, "Expected '{' for switch body.");

        var cases = new List<BtSwitchCase>();
        while (!IsAtEnd() && !Check(BtTokenKind.RBrace))
        {
            if (Match(BtTokenKind.Case))
            {
                var matchExpr = ParseExpression();
                Consume(BtTokenKind.Colon, "Expected ':' after case expression.");
                var caseStmts = new List<BtStmt>();
                while (!IsAtEnd() && !Check(BtTokenKind.Case) && !Check(BtTokenKind.Default) && !Check(BtTokenKind.RBrace))
                {
                    if (Match(BtTokenKind.Semicolon)) continue;
                    caseStmts.Add(ParseStatement());
                }
                cases.Add(new BtSwitchCase(matchExpr, caseStmts));
            }
            else if (Match(BtTokenKind.Default))
            {
                Consume(BtTokenKind.Colon, "Expected ':' after default.");
                var defStmts = new List<BtStmt>();
                while (!IsAtEnd() && !Check(BtTokenKind.Case) && !Check(BtTokenKind.Default) && !Check(BtTokenKind.RBrace))
                {
                    if (Match(BtTokenKind.Semicolon)) continue;
                    defStmts.Add(ParseStatement());
                }
                cases.Add(new BtSwitchCase(null, defStmts));
            }
            else
            {
                Advance();
            }
        }
        Consume(BtTokenKind.RBrace, "Expected '}' after switch cases.");
        return new BtSwitchStmt(val, cases, line);
    }

    private BtStmt ParseTypedef(int line)
    {
        if (Check(BtTokenKind.Struct) || Check(BtTokenKind.Union))
        {
            var structStmt = (BtStructDefStmt)ParseStructOrUnion(isTypedef: true);
            return structStmt;
        }
        if (Check(BtTokenKind.Enum))
        {
            var enumStmt = (BtEnumDefStmt)ParseEnum(isTypedef: true);
            return enumStmt;
        }

        string existingType = ParseTypeName();
        string alias = Consume(BtTokenKind.Identifier, "Expected typedef alias name.").Lexeme;
        int? fixedArray = null;
        if (Match(BtTokenKind.LBracket))
        {
            if (Check(BtTokenKind.IntegerLiteral))
                fixedArray = (int)Advance().IntValue;
            Consume(BtTokenKind.RBracket, "Expected ']' in typedef array.");
        }
        ConsumeOptional(BtTokenKind.Semicolon);
        _userTypes.Add(alias);
        return new BtTypedefStmt(existingType, alias, fixedArray, line);
    }

    private BtStmt ParseStructOrUnion(bool isTypedef = false)
    {
        var startTok = Advance(); // struct or union
        bool isUnion = startTok.Kind == BtTokenKind.Union;

        string typeName = "";
        if (Check(BtTokenKind.Identifier))
        {
            typeName = Advance().Lexeme;
            _userTypes.Add(typeName);
        }

        var parameters = new List<string>();
        if (Match(BtTokenKind.LParen))
        {
            while (!IsAtEnd() && !Check(BtTokenKind.RParen))
            {
                string paramType = ParseTypeName();
                if (Check(BtTokenKind.Identifier))
                    parameters.Add(Advance().Lexeme);
                Match(BtTokenKind.Comma);
            }
            Consume(BtTokenKind.RParen, "Expected ')' after struct parameters.");
        }

        // Handle 'struct TypeName instanceName;' without inline body
        if (!Check(BtTokenKind.LBrace))
        {
            return ParseVarDeclarationAfterType(isLocal: false, typeName, startTok.Line);
        }

        Consume(BtTokenKind.LBrace, "Expected '{' for struct body.");
        var body = new List<BtStmt>();
        while (!IsAtEnd() && !Check(BtTokenKind.RBrace))
        {
            if (Match(BtTokenKind.Semicolon)) continue;
            body.Add(ParseStatement());
        }
        Consume(BtTokenKind.RBrace, "Expected '}' after struct body.");

        string? instanceName = null;
        BtExpr? arrayLen = null;
        if (Check(BtTokenKind.Identifier))
        {
            string trailingIdent = Advance().Lexeme;
            if (isTypedef)
            {
                if (string.IsNullOrEmpty(typeName))
                    typeName = trailingIdent;
                _userTypes.Add(trailingIdent);
            }
            else
            {
                instanceName = trailingIdent;
                // Optional struct arguments e.g. CHUNK chunk(16)
                if (Match(BtTokenKind.LParen))
                {
                    while (!IsAtEnd() && !Check(BtTokenKind.RParen))
                        Advance();
                    ConsumeOptional(BtTokenKind.RParen);
                }
                if (Match(BtTokenKind.LBracket))
                {
                    if (!Check(BtTokenKind.RBracket))
                        arrayLen = ParseExpression();
                    Consume(BtTokenKind.RBracket, "Expected ']' after struct array size.");
                }
            }
        }

        var attrs = ParseOptionalAttributes();
        ConsumeOptional(BtTokenKind.Semicolon);

        if (string.IsNullOrEmpty(typeName))
            typeName = instanceName ?? $"AnonStruct_{startTok.Line}";

        _userTypes.Add(typeName);
        return new BtStructDefStmt(isUnion, typeName, parameters, body, instanceName, arrayLen, attrs, startTok.Line);
    }

    private BtStmt ParseEnum(bool isTypedef = false)
    {
        var startTok = Consume(BtTokenKind.Enum, "Expected 'enum'.");
        string underlyingType = "int";

        if (Match(BtTokenKind.Less))
        {
            underlyingType = ParseTypeName();
            Consume(BtTokenKind.Greater, "Expected '>' after enum underlying type.");
        }

        string enumName = "";
        if (Check(BtTokenKind.Identifier))
        {
            enumName = Advance().Lexeme;
            _userTypes.Add(enumName);
        }

        if (!Check(BtTokenKind.LBrace))
        {
            return ParseVarDeclarationAfterType(isLocal: false, enumName, startTok.Line);
        }

        Consume(BtTokenKind.LBrace, "Expected '{' for enum body.");
        var members = new List<BtEnumMember>();
        while (!IsAtEnd() && !Check(BtTokenKind.RBrace))
        {
            if (!Check(BtTokenKind.Identifier))
            {
                Advance();
                continue;
            }
            string mName = Advance().Lexeme;
            BtExpr? mVal = null;
            if (Match(BtTokenKind.Assign))
                mVal = ParseExpression(allowComma: false, allowGreater: true);
            members.Add(new BtEnumMember(mName, mVal));
            Match(BtTokenKind.Comma);
        }
        Consume(BtTokenKind.RBrace, "Expected '}' after enum members.");

        string? instanceName = null;
        if (Check(BtTokenKind.Identifier))
        {
            string trailing = Advance().Lexeme;
            if (isTypedef)
            {
                if (string.IsNullOrEmpty(enumName))
                    enumName = trailing;
                _userTypes.Add(trailing);
            }
            else
            {
                instanceName = trailing;
            }
        }

        var attrs = ParseOptionalAttributes();
        ConsumeOptional(BtTokenKind.Semicolon);

        if (string.IsNullOrEmpty(enumName))
            enumName = instanceName ?? $"AnonEnum_{startTok.Line}";
        _userTypes.Add(enumName);

        return new BtEnumDefStmt(underlyingType, enumName, members, instanceName, attrs, startTok.Line);
    }

    private BtFunctionDefStmt ParseFunctionDef(string returnType, int line)
    {
        string funcName = Consume(BtTokenKind.Identifier, "Expected function name.").Lexeme;
        Consume(BtTokenKind.LParen, "Expected '(' after function name.");
        var parameters = new List<BtFunctionParameter>();
        while (!IsAtEnd() && !Check(BtTokenKind.RParen))
        {
            Match(BtTokenKind.Const);
            string pType = ParseTypeName();
            Match(BtTokenKind.Amp);
            string pName = Check(BtTokenKind.Identifier) ? Advance().Lexeme : $"arg{parameters.Count}";
            if (Match(BtTokenKind.LBracket))
            {
                while (!IsAtEnd() && !Check(BtTokenKind.RBracket)) Advance();
                ConsumeOptional(BtTokenKind.RBracket);
            }
            parameters.Add(new BtFunctionParameter(pType, pName));
            Match(BtTokenKind.Comma);
        }
        Consume(BtTokenKind.RParen, "Expected ')' after function parameters.");
        Consume(BtTokenKind.LBrace, "Expected '{' for function body.");
        var body = ParseBlock(line);
        return new BtFunctionDefStmt(returnType, funcName, parameters, body, line);
    }

    private BtStmt ParseVarDeclarationAfterType(bool isLocal, string typeName, int line)
    {
        var decls = new List<BtStmt>();

        while (true)
        {
            string varName = Check(BtTokenKind.Identifier)
                ? Advance().Lexeme
                : $"field_{line}_{_pos}";

            // Optional struct constructor args e.g. RECORD rec(10)
            if (Match(BtTokenKind.LParen))
            {
                while (!IsAtEnd() && !Check(BtTokenKind.RParen))
                    Advance();
                ConsumeOptional(BtTokenKind.RParen);
            }

            BtExpr? arrayLen = null;
            if (Match(BtTokenKind.LBracket))
            {
                if (!Check(BtTokenKind.RBracket))
                    arrayLen = ParseExpression();
                Consume(BtTokenKind.RBracket, "Expected ']' after array size.");
            }

            int? bitfieldWidth = null;
            if (Match(BtTokenKind.Colon))
            {
                if (Check(BtTokenKind.IntegerLiteral))
                    bitfieldWidth = (int)Advance().IntValue;
            }

            BtExpr? initializer = null;
            if (Match(BtTokenKind.Assign))
            {
                initializer = ParseExpression(allowComma: false, allowGreater: false);
            }

            var attrs = ParseOptionalAttributes();
            decls.Add(new BtVarDeclStmt(isLocal, typeName, varName, arrayLen, bitfieldWidth, initializer, attrs, line));

            if (!Match(BtTokenKind.Comma))
                break;
        }

        ConsumeOptional(BtTokenKind.Semicolon);
        return decls.Count == 1 ? decls[0] : new BtBlockStmt(decls, line);
    }

    private BtFieldAttributes? ParseOptionalAttributes()
    {
        if (!Match(BtTokenKind.Less))
            return null;

        BtExpr? bgColor = null;
        BtExpr? fgColor = null;
        string? format = null;
        BtExpr? comment = null;
        string? nameOverride = null;
        bool isHidden = false;
        bool isOpen = false;

        while (!IsAtEnd() && !Check(BtTokenKind.Greater))
        {
            if (!Check(BtTokenKind.Identifier))
            {
                Advance();
                continue;
            }

            string key = Advance().Lexeme;
            if (Match(BtTokenKind.Assign))
            {
                if (string.Equals(key, "bgcolor", StringComparison.OrdinalIgnoreCase))
                {
                    bgColor = ParseAttributeValueExpr();
                }
                else if (string.Equals(key, "fgcolor", StringComparison.OrdinalIgnoreCase))
                {
                    fgColor = ParseAttributeValueExpr();
                }
                else if (string.Equals(key, "format", StringComparison.OrdinalIgnoreCase))
                {
                    format = Check(BtTokenKind.Identifier) ? Advance().Lexeme : ParseAttributeValueExpr().ToString();
                }
                else if (string.Equals(key, "comment", StringComparison.OrdinalIgnoreCase))
                {
                    comment = ParseAttributeValueExpr();
                }
                else if (string.Equals(key, "name", StringComparison.OrdinalIgnoreCase))
                {
                    if (Check(BtTokenKind.StringLiteral) || Check(BtTokenKind.Identifier))
                        nameOverride = Advance().Lexeme;
                    else
                        _ = ParseAttributeValueExpr();
                }
                else if (string.Equals(key, "hidden", StringComparison.OrdinalIgnoreCase))
                {
                    var v = ParseAttributeValueExpr();
                    isHidden = v is BtIntLiteralExpr { Value: not 0 } or BtIdentifierExpr { Name: "true" or "TRUE" };
                }
                else if (string.Equals(key, "open", StringComparison.OrdinalIgnoreCase))
                {
                    var v = ParseAttributeValueExpr();
                    isOpen = v is BtIntLiteralExpr { Value: not 0 } or BtIdentifierExpr { Name: "true" or "TRUE" or "suppress" };
                }
                else
                {
                    _ = ParseAttributeValueExpr();
                }
            }

            Match(BtTokenKind.Comma);
        }

        ConsumeOptional(BtTokenKind.Greater);
        return new BtFieldAttributes(bgColor, fgColor, format, comment, nameOverride, isHidden, isOpen);
    }

    private BtExpr ParseAttributeValueExpr()
    {
        return ParsePrimary();
    }

    private bool IsStartOfDeclaration()
    {
        var tok = Peek();
        if (tok.Kind is BtTokenKind.Unsigned or BtTokenKind.Signed)
            return true;

        if (tok.Kind == BtTokenKind.Identifier)
        {
            string lex = tok.Lexeme;
            if (BuiltinTypeNames.Contains(lex) || _userTypes.Contains(lex))
            {
                var next = Peek(1);
                return next.Kind == BtTokenKind.Identifier;
            }
        }
        return false;
    }

    private bool IsFunctionDefinitionLookahead()
    {
        int i = _pos + 1; // at '('
        int depth = 0;
        while (i < _tokens.Count)
        {
            var k = _tokens[i].Kind;
            if (k == BtTokenKind.LParen) depth++;
            else if (k == BtTokenKind.RParen)
            {
                depth--;
                if (depth == 0)
                {
                    return i + 1 < _tokens.Count && _tokens[i + 1].Kind == BtTokenKind.LBrace;
                }
            }
            i++;
        }
        return false;
    }

    private string ParseTypeName()
    {
        bool isUnsigned = false;
        if (Match(BtTokenKind.Unsigned))
            isUnsigned = true;
        else if (Match(BtTokenKind.Signed))
            isUnsigned = false;

        Match(BtTokenKind.Struct);
        Match(BtTokenKind.Enum);

        if (Check(BtTokenKind.Identifier))
        {
            string baseType = Advance().Lexeme;
            // Handle "unsigned int", "unsigned char", "unsigned short", "unsigned long", "long long"
            if (baseType.Equals("long", StringComparison.OrdinalIgnoreCase) &&
                Check(BtTokenKind.Identifier) &&
                Peek().Lexeme.Equals("long", StringComparison.OrdinalIgnoreCase))
            {
                Advance();
                return isUnsigned ? "uint64" : "int64";
            }

            if (isUnsigned)
            {
                return baseType.ToLowerInvariant() switch
                {
                    "char" or "byte" => "uchar",
                    "short" or "int16" => "ushort",
                    "int" or "long" or "int32" => "uint",
                    "int64" or "quad" or "__int64" => "uint64",
                    _ => "u" + baseType
                };
            }
            return baseType;
        }

        return isUnsigned ? "uint" : "int";
    }

    // Expression Parsing (Precedence Climbing)
    private BtExpr ParseExpression(bool allowComma = true, bool allowGreater = true)
    {
        return ParseAssignment(allowGreater);
    }

    private BtExpr ParseAssignment(bool allowGreater)
    {
        var expr = ParseTernary(allowGreater);

        if (Check(BtTokenKind.Assign) ||
            Check(BtTokenKind.PlusAssign) ||
            Check(BtTokenKind.MinusAssign) ||
            Check(BtTokenKind.StarAssign) ||
            Check(BtTokenKind.SlashAssign) ||
            Check(BtTokenKind.AmpAssign) ||
            Check(BtTokenKind.PipeAssign) ||
            Check(BtTokenKind.CaretAssign))
        {
            var op = Advance();
            var right = ParseAssignment(allowGreater);
            return new BtAssignExpr(op.Lexeme, expr, right, op.Line);
        }

        return expr;
    }

    private BtExpr ParseTernary(bool allowGreater)
    {
        var expr = ParseLogicalOr(allowGreater);
        if (Match(BtTokenKind.Question))
        {
            var trueExpr = ParseExpression(allowComma: false, allowGreater: allowGreater);
            Consume(BtTokenKind.Colon, "Expected ':' in ternary expression.");
            var falseExpr = ParseTernary(allowGreater);
            return new BtTernaryExpr(expr, trueExpr, falseExpr, expr.Line);
        }
        return expr;
    }

    private BtExpr ParseLogicalOr(bool allowGreater)
    {
        var expr = ParseLogicalAnd(allowGreater);
        while (Match(BtTokenKind.OrOr))
        {
            var op = Previous();
            var right = ParseLogicalAnd(allowGreater);
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseLogicalAnd(bool allowGreater)
    {
        var expr = ParseBitwiseOr(allowGreater);
        while (Match(BtTokenKind.AndAnd))
        {
            var op = Previous();
            var right = ParseBitwiseOr(allowGreater);
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseBitwiseOr(bool allowGreater)
    {
        var expr = ParseBitwiseXor(allowGreater);
        while (Match(BtTokenKind.Pipe))
        {
            var op = Previous();
            var right = ParseBitwiseXor(allowGreater);
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseBitwiseXor(bool allowGreater)
    {
        var expr = ParseBitwiseAnd(allowGreater);
        while (Match(BtTokenKind.Caret))
        {
            var op = Previous();
            var right = ParseBitwiseAnd(allowGreater);
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseBitwiseAnd(bool allowGreater)
    {
        var expr = ParseEquality(allowGreater);
        while (Match(BtTokenKind.Amp))
        {
            var op = Previous();
            var right = ParseEquality(allowGreater);
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseEquality(bool allowGreater)
    {
        var expr = ParseRelational(allowGreater);
        while (Match(BtTokenKind.EqualEqual) || Match(BtTokenKind.NotEqual))
        {
            var op = Previous();
            var right = ParseRelational(allowGreater);
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseRelational(bool allowGreater)
    {
        var expr = ParseShift();
        while (Check(BtTokenKind.Less) ||
               Check(BtTokenKind.LessEqual) ||
               Check(BtTokenKind.GreaterEqual) ||
               (allowGreater && Check(BtTokenKind.Greater)))
        {
            // Avoid consuming `<bgcolor=...>` field attributes as a `<` operator!
            if (Check(BtTokenKind.Less) && LooksLikeAttributeBlock())
                break;

            var op = Advance();
            var right = ParseShift();
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private bool LooksLikeAttributeBlock()
    {
        if (Peek().Kind != BtTokenKind.Less) return false;
        var next = Peek(1);
        var next2 = Peek(2);
        return next.Kind == BtTokenKind.Identifier && next2.Kind == BtTokenKind.Assign;
    }

    private BtExpr ParseShift()
    {
        var expr = ParseAdditive();
        while (Match(BtTokenKind.ShiftLeft) || Match(BtTokenKind.ShiftRight))
        {
            var op = Previous();
            var right = ParseAdditive();
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseAdditive()
    {
        var expr = ParseMultiplicative();
        while (Match(BtTokenKind.Plus) || Match(BtTokenKind.Minus))
        {
            var op = Previous();
            var right = ParseMultiplicative();
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseMultiplicative()
    {
        var expr = ParseUnary();
        while (Match(BtTokenKind.Star) || Match(BtTokenKind.Slash) || Match(BtTokenKind.Percent))
        {
            var op = Previous();
            var right = ParseUnary();
            expr = new BtBinaryExpr(op.Lexeme, expr, right, op.Line);
        }
        return expr;
    }

    private BtExpr ParseUnary()
    {
        if (Match(BtTokenKind.Minus) || Match(BtTokenKind.Plus) ||
            Match(BtTokenKind.Bang) || Match(BtTokenKind.Tilde) ||
            Match(BtTokenKind.PlusPlus) || Match(BtTokenKind.MinusMinus))
        {
            var op = Previous();
            var right = ParseUnary();
            return new BtUnaryExpr(op.Lexeme, right, IsPostfix: false, op.Line);
        }

        if (Match(BtTokenKind.Sizeof))
        {
            var tok = Previous();
            Consume(BtTokenKind.LParen, "Expected '(' after sizeof.");
            string target = Check(BtTokenKind.Identifier) ? Advance().Lexeme : "int";
            Consume(BtTokenKind.RParen, "Expected ')' after sizeof argument.");
            return new BtSizeofExpr(target, tok.Line);
        }

        return ParsePostfix();
    }

    private BtExpr ParsePostfix()
    {
        var expr = ParsePrimary();

        while (true)
        {
            if (Match(BtTokenKind.Dot))
            {
                string member = Consume(BtTokenKind.Identifier, "Expected member name after '.'.").Lexeme;
                expr = new BtMemberAccessExpr(expr, member, expr.Line);
            }
            else if (Match(BtTokenKind.LBracket))
            {
                var idx = ParseExpression();
                Consume(BtTokenKind.RBracket, "Expected ']' after index.");
                expr = new BtIndexExpr(expr, idx, expr.Line);
            }
            else if (Match(BtTokenKind.PlusPlus) || Match(BtTokenKind.MinusMinus))
            {
                var op = Previous();
                expr = new BtUnaryExpr(op.Lexeme, expr, IsPostfix: true, op.Line);
            }
            else
            {
                break;
            }
        }

        return expr;
    }

    private BtExpr ParsePrimary()
    {
        var tok = Peek();

        if (Match(BtTokenKind.IntegerLiteral) || Match(BtTokenKind.CharLiteral) ||
            Match(BtTokenKind.True) || Match(BtTokenKind.False))
        {
            return new BtIntLiteralExpr(tok.IntValue, tok.Lexeme, tok.Line);
        }

        if (Match(BtTokenKind.FloatLiteral))
        {
            return new BtFloatLiteralExpr(tok.FloatValue, tok.Line);
        }

        if (Match(BtTokenKind.StringLiteral))
        {
            return new BtStringLiteralExpr(tok.Lexeme, tok.Line);
        }

        if (Match(BtTokenKind.LParen))
        {
            // Check for C-style type cast: (uint32)expr
            if (Check(BtTokenKind.Identifier) &&
                (BuiltinTypeNames.Contains(Peek().Lexeme) || _userTypes.Contains(Peek().Lexeme)) &&
                Peek(1).Kind == BtTokenKind.RParen)
            {
                Advance(); // type
                Advance(); // )
                return ParseUnary();
            }

            var inner = ParseExpression();
            Consume(BtTokenKind.RParen, "Expected ')' after expression.");
            return inner;
        }

        if (Match(BtTokenKind.Identifier))
        {
            if (Match(BtTokenKind.LParen))
            {
                var args = new List<BtExpr>();
                if (!Check(BtTokenKind.RParen))
                {
                    do
                    {
                        args.Add(ParseExpression(allowComma: false));
                    } while (Match(BtTokenKind.Comma));
                }
                Consume(BtTokenKind.RParen, "Expected ')' after function arguments.");
                return new BtCallExpr(tok.Lexeme, args, tok.Line);
            }
            return new BtIdentifierExpr(tok.Lexeme, tok.Line);
        }

        // Graceful recovery on unexpected token
        Advance();
        return new BtIntLiteralExpr(0, "0", tok.Line);
    }

    // Token helpers
    private BtToken Peek(int offset = 0)
    {
        int idx = _pos + offset;
        return idx < _tokens.Count ? _tokens[idx] : _tokens[^1];
    }

    private BtToken Previous() => _tokens[Math.Max(0, _pos - 1)];

    private bool IsAtEnd() => Peek().Kind == BtTokenKind.Eof;

    private bool Check(BtTokenKind kind) => !IsAtEnd() && Peek().Kind == kind;

    private bool Match(BtTokenKind kind)
    {
        if (Check(kind))
        {
            Advance();
            return true;
        }
        return false;
    }

    private BtToken Advance()
    {
        if (!IsAtEnd()) _pos++;
        return Previous();
    }

    private BtToken Consume(BtTokenKind kind, string message)
    {
        if (Check(kind)) return Advance();
        throw new FormatException($"[Line {Peek().Line}:{Peek().Column}] {message} (Found '{Peek().Lexeme}')");
    }

    private void ConsumeOptional(BtTokenKind kind)
    {
        if (Check(kind)) Advance();
    }
}

