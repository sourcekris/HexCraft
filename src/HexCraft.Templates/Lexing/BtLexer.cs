using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HexCraft.Templates.Lexing;

public enum BtTokenKind
{
    Eof,
    Identifier,
    IntegerLiteral,
    FloatLiteral,
    StringLiteral,
    CharLiteral,

    // Keywords
    Struct,
    Union,
    Enum,
    Typedef,
    Local,
    Const,
    Unsigned,
    Signed,
    If,
    Else,
    While,
    For,
    Do,
    Switch,
    Case,
    Default,
    Break,
    Continue,
    Return,
    Sizeof,
    True,
    False,

    // Punctuation & Operators
    LBrace,         // {
    RBrace,         // }
    LParen,         // (
    RParen,         // )
    LBracket,       // [
    RBracket,       // ]
    Semicolon,      // ;
    Comma,          // ,
    Dot,            // .
    Question,       // ?
    Colon,          // :
    Tilde,          // ~
    Bang,           // !
    Plus,           // +
    Minus,          // -
    Star,           // *
    Slash,          // /
    Percent,        // %
    Amp,            // &
    Pipe,           // |
    Caret,          // ^
    Assign,         // =
    Less,           // <
    Greater,        // >

    PlusPlus,       // ++
    MinusMinus,     // --
    PlusAssign,     // +=
    MinusAssign,    // -=
    StarAssign,     // *=
    SlashAssign,    // /=
    AmpAssign,      // &=
    PipeAssign,     // |=
    CaretAssign,    // ^=
    EqualEqual,     // ==
    NotEqual,       // !=
    LessEqual,      // <=
    GreaterEqual,   // >=
    AndAnd,         // &&
    OrOr,           // ||
    ShiftLeft,      // <<
    ShiftRight      // >>
}

public readonly record struct BtToken(
    BtTokenKind Kind,
    string Lexeme,
    long IntValue,
    double FloatValue,
    int Line,
    int Column);

/// <summary>
/// Lexer for 010 Editor Binary Templates (.bt), supporting C-style syntax,
/// hex/binary/decimal literals, character literals, and #define preprocessor constants.
/// </summary>
public sealed class BtLexer
{
    private static readonly Dictionary<string, BtTokenKind> Keywords = new(StringComparer.Ordinal)
    {
        ["struct"] = BtTokenKind.Struct,
        ["union"] = BtTokenKind.Union,
        ["enum"] = BtTokenKind.Enum,
        ["typedef"] = BtTokenKind.Typedef,
        ["local"] = BtTokenKind.Local,
        ["const"] = BtTokenKind.Const,
        ["unsigned"] = BtTokenKind.Unsigned,
        ["signed"] = BtTokenKind.Signed,
        ["if"] = BtTokenKind.If,
        ["else"] = BtTokenKind.Else,
        ["while"] = BtTokenKind.While,
        ["for"] = BtTokenKind.For,
        ["do"] = BtTokenKind.Do,
        ["switch"] = BtTokenKind.Switch,
        ["case"] = BtTokenKind.Case,
        ["default"] = BtTokenKind.Default,
        ["break"] = BtTokenKind.Break,
        ["continue"] = BtTokenKind.Continue,
        ["return"] = BtTokenKind.Return,
        ["sizeof"] = BtTokenKind.Sizeof,
        ["true"] = BtTokenKind.True,
        ["false"] = BtTokenKind.False,
        ["TRUE"] = BtTokenKind.True,
        ["FALSE"] = BtTokenKind.False
    };

    public static List<BtToken> Tokenize(string source)
    {
        string preprocessed = PreprocessDefines(source ?? string.Empty);
        var tokens = new List<BtToken>();
        int pos = 0;
        int line = 1;
        int col = 1;
        int len = preprocessed.Length;

        char Peek(int offset = 0) => pos + offset < len ? preprocessed[pos + offset] : '\0';
        char Advance()
        {
            char c = Peek();
            pos++;
            if (c == '\n')
            {
                line++;
                col = 1;
            }
            else
            {
                col++;
            }
            return c;
        }

        while (pos < len)
        {
            char c = Peek();

            // Skip whitespace
            if (char.IsWhiteSpace(c))
            {
                Advance();
                continue;
            }

            // Single-line comment
            if (c == '/' && Peek(1) == '/')
            {
                while (pos < len && Peek() != '\n')
                    Advance();
                continue;
            }

            // Multi-line comment
            if (c == '/' && Peek(1) == '*')
            {
                Advance();
                Advance();
                while (pos < len && !(Peek() == '*' && Peek(1) == '/'))
                    Advance();
                if (pos < len)
                {
                    Advance();
                    Advance();
                }
                continue;
            }

            // Skip any remaining preprocessor lines
            if (c == '#')
            {
                while (pos < len && Peek() != '\n')
                    Advance();
                continue;
            }

            int startLine = line;
            int startCol = col;

            // String literal
            if (c == '"')
            {
                Advance();
                var sb = new StringBuilder();
                while (pos < len && Peek() != '"')
                {
                    char ch = Advance();
                    if (ch == '\\' && pos < len)
                    {
                        char esc = Advance();
                        sb.Append(esc switch
                        {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '0' => '\0',
                            '\\' => '\\',
                            '"' => '"',
                            _ => esc
                        });
                    }
                    else
                    {
                        sb.Append(ch);
                    }
                }
                if (Peek() == '"') Advance();
                tokens.Add(new BtToken(BtTokenKind.StringLiteral, sb.ToString(), 0, 0, startLine, startCol));
                continue;
            }

            // Character literal
            if (c == '\'')
            {
                Advance();
                long charVal = 0;
                if (pos < len && Peek() != '\'')
                {
                    char ch = Advance();
                    if (ch == '\\' && pos < len)
                    {
                        char esc = Advance();
                        charVal = esc switch
                        {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '0' => '\0',
                            '\\' => '\\',
                            '\'' => '\'',
                            _ => esc
                        };
                    }
                    else
                    {
                        charVal = ch;
                    }
                }
                while (pos < len && Peek() != '\'')
                    Advance();
                if (Peek() == '\'') Advance();
                tokens.Add(new BtToken(BtTokenKind.CharLiteral, charVal.ToString(), charVal, charVal, startLine, startCol));
                continue;
            }

            // Numeric literal
            if (char.IsDigit(c))
            {
                var sb = new StringBuilder();
                bool isHex = false;
                bool isBin = false;
                bool isFloat = false;

                if (c == '0' && (Peek(1) == 'x' || Peek(1) == 'X'))
                {
                    isHex = true;
                    sb.Append(Advance());
                    sb.Append(Advance());
                    while (pos < len && IsHexDigit(Peek()))
                        sb.Append(Advance());
                }
                else if (c == '0' && (Peek(1) == 'b' || Peek(1) == 'B'))
                {
                    isBin = true;
                    Advance();
                    Advance();
                    while (pos < len && (Peek() == '0' || Peek() == '1' || Peek() == '_'))
                    {
                        char bit = Advance();
                        if (bit != '_') sb.Append(bit);
                    }
                }
                else
                {
                    while (pos < len && (char.IsDigit(Peek()) || Peek() == '.'))
                    {
                        if (Peek() == '.')
                            isFloat = true;
                        sb.Append(Advance());
                    }
                }

                // Consume integer/float suffixes like u, U, l, L, f, F, h
                while (pos < len && (Peek() is 'u' or 'U' or 'l' or 'L' or 'f' or 'F'))
                    Advance();

                string raw = sb.ToString();
                if (isFloat)
                {
                    double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double dVal);
                    tokens.Add(new BtToken(BtTokenKind.FloatLiteral, raw, (long)dVal, dVal, startLine, startCol));
                }
                else if (isHex)
                {
                    string hexDigits = raw.Length > 2 ? raw[2..] : "0";
                    ulong.TryParse(hexDigits, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong uVal);
                    long lVal = unchecked((long)uVal);
                    tokens.Add(new BtToken(BtTokenKind.IntegerLiteral, raw, lVal, lVal, startLine, startCol));
                }
                else if (isBin)
                {
                    long lVal = sb.Length > 0 ? Convert.ToInt64(raw, 2) : 0;
                    tokens.Add(new BtToken(BtTokenKind.IntegerLiteral, "0b" + raw, lVal, lVal, startLine, startCol));
                }
                else
                {
                    ulong.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong uVal);
                    long lVal = unchecked((long)uVal);
                    tokens.Add(new BtToken(BtTokenKind.IntegerLiteral, raw, lVal, lVal, startLine, startCol));
                }
                continue;
            }

            // Identifier or Keyword
            if (char.IsLetter(c) || c == '_')
            {
                var sb = new StringBuilder();
                while (pos < len && (char.IsLetterOrDigit(Peek()) || Peek() == '_'))
                    sb.Append(Advance());

                string ident = sb.ToString();
                if (Keywords.TryGetValue(ident, out var kwKind))
                {
                    long intVal = kwKind == BtTokenKind.True ? 1 : 0;
                    tokens.Add(new BtToken(kwKind, ident, intVal, intVal, startLine, startCol));
                }
                else
                {
                    tokens.Add(new BtToken(BtTokenKind.Identifier, ident, 0, 0, startLine, startCol));
                }
                continue;
            }

            // Two-character operators
            char next = Peek(1);
            string two = new string(new[] { c, next });
            BtTokenKind? twoKind = two switch
            {
                "++" => BtTokenKind.PlusPlus,
                "--" => BtTokenKind.MinusMinus,
                "+=" => BtTokenKind.PlusAssign,
                "-=" => BtTokenKind.MinusAssign,
                "*=" => BtTokenKind.StarAssign,
                "/=" => BtTokenKind.SlashAssign,
                "&=" => BtTokenKind.AmpAssign,
                "|=" => BtTokenKind.PipeAssign,
                "^=" => BtTokenKind.CaretAssign,
                "==" => BtTokenKind.EqualEqual,
                "!=" => BtTokenKind.NotEqual,
                "<=" => BtTokenKind.LessEqual,
                ">=" => BtTokenKind.GreaterEqual,
                "&&" => BtTokenKind.AndAnd,
                "||" => BtTokenKind.OrOr,
                "<<" => BtTokenKind.ShiftLeft,
                ">>" => BtTokenKind.ShiftRight,
                _ => null
            };

            if (twoKind.HasValue)
            {
                Advance();
                Advance();
                tokens.Add(new BtToken(twoKind.Value, two, 0, 0, startLine, startCol));
                continue;
            }

            // Single-character operators & punctuation
            Advance();
            BtTokenKind singleKind = c switch
            {
                '{' => BtTokenKind.LBrace,
                '}' => BtTokenKind.RBrace,
                '(' => BtTokenKind.LParen,
                ')' => BtTokenKind.RParen,
                '[' => BtTokenKind.LBracket,
                ']' => BtTokenKind.RBracket,
                ';' => BtTokenKind.Semicolon,
                ',' => BtTokenKind.Comma,
                '.' => BtTokenKind.Dot,
                '?' => BtTokenKind.Question,
                ':' => BtTokenKind.Colon,
                '~' => BtTokenKind.Tilde,
                '!' => BtTokenKind.Bang,
                '+' => BtTokenKind.Plus,
                '-' => BtTokenKind.Minus,
                '*' => BtTokenKind.Star,
                '/' => BtTokenKind.Slash,
                '%' => BtTokenKind.Percent,
                '&' => BtTokenKind.Amp,
                '|' => BtTokenKind.Pipe,
                '^' => BtTokenKind.Caret,
                '=' => BtTokenKind.Assign,
                '<' => BtTokenKind.Less,
                '>' => BtTokenKind.Greater,
                _ => BtTokenKind.Semicolon
            };

            tokens.Add(new BtToken(singleKind, c.ToString(), 0, 0, startLine, startCol));
        }

        tokens.Add(new BtToken(BtTokenKind.Eof, "", 0, 0, line, col));
        return tokens;
    }

    private static bool IsHexDigit(char c)
    {
        return char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /// <summary>
    /// Expands simple object-like #define NAME VALUE directives while preserving line numbers.
    /// </summary>
    private static string PreprocessDefines(string source)
    {
        var defines = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] lines = source.Replace("\r\n", "\n").Split('\n');
        var output = new StringBuilder(source.Length);

        foreach (string rawLine in lines)
        {
            string trimmed = rawLine.Trim();
            if (trimmed.StartsWith("#define ", StringComparison.Ordinal))
            {
                string rest = trimmed[8..].Trim();
                int spaceIdx = rest.IndexOfAny(new[] { ' ', '\t' });
                if (spaceIdx > 0)
                {
                    string macroName = rest[..spaceIdx].Trim();
                    string macroVal = rest[(spaceIdx + 1)..].Trim();
                    int commentIdx = macroVal.IndexOf("//", StringComparison.Ordinal);
                    if (commentIdx >= 0)
                        macroVal = macroVal[..commentIdx].Trim();

                    if (!macroName.Contains('('))
                        defines[macroName] = macroVal;
                }
                output.Append('\n');
                continue;
            }

            string expanded = rawLine;
            foreach (var kvp in defines)
            {
                expanded = ReplaceWholeWord(expanded, kvp.Key, kvp.Value);
            }
            output.Append(expanded).Append('\n');
        }

        return output.ToString();
    }

    private static string ReplaceWholeWord(string input, string word, string replacement)
    {
        if (string.IsNullOrEmpty(word) || !input.Contains(word, StringComparison.Ordinal))
            return input;

        var sb = new StringBuilder(input.Length);
        int i = 0;
        while (i < input.Length)
        {
            int idx = input.IndexOf(word, i, StringComparison.Ordinal);
            if (idx < 0)
            {
                sb.Append(input, i, input.Length - i);
                break;
            }

            bool leftBoundary = idx == 0 || !(char.IsLetterOrDigit(input[idx - 1]) || input[idx - 1] == '_');
            int endIdx = idx + word.Length;
            bool rightBoundary = endIdx >= input.Length || !(char.IsLetterOrDigit(input[endIdx]) || input[endIdx] == '_');

            if (leftBoundary && rightBoundary)
            {
                sb.Append(input, i, idx - i);
                sb.Append(replacement);
                i = endIdx;
            }
            else
            {
                sb.Append(input, i, idx - i + 1);
                i = idx + 1;
            }
        }
        return sb.ToString();
    }
}

