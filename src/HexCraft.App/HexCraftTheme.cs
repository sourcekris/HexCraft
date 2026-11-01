using Avalonia.Media;

namespace HexCraft.App;

public enum HexCraftThemeKind
{
    Dark,
    Light
}

/// <summary>
/// Centralized color palette for HexCraft's Dark and Light themes.
/// </summary>
public sealed class HexCraftThemePalette
{
    public HexCraftThemeKind Kind { get; init; }
    public string WindowBg { get; init; } = "";
    public string ToolbarBg { get; init; } = "";
    public string ToolbarBorder { get; init; } = "";
    public string PaneBg { get; init; } = "";
    public string PaneHeaderBg { get; init; } = "";
    public string PaneBorder { get; init; } = "";
    public string EditorBg { get; init; } = "";
    public string EditorHeaderBg { get; init; } = "";
    public string EditorGutterBg { get; init; } = "";
    public string EditorGridLine { get; init; } = "";
    public string ConsoleBg { get; init; } = "";
    public string CardBg { get; init; } = "";
    public string RowBg { get; init; } = "";
    public string ButtonBg { get; init; } = "";
    public string ActiveTabBg { get; init; } = "";
    public string InactiveTabBg { get; init; } = "";

    public string PrimaryText { get; init; } = "";
    public string SecondaryText { get; init; } = "";
    public string MutedText { get; init; } = "";
    public string NullByteText { get; init; } = "";
    public string AddressText { get; init; } = "";
    public string AsciiText { get; init; } = "";
    public string ModifiedByteText { get; init; } = "";

    public string AccentBlue { get; init; } = "";
    public string AccentCyan { get; init; } = "";
    public string AccentGreen { get; init; } = "";
    public string AccentGold { get; init; } = "";
    public string AccentPurple { get; init; } = "";
    public string AccentRed { get; init; } = "";
    public string SelectionFill { get; init; } = "";
    public string CursorFill { get; init; } = "";

    public static HexCraftThemePalette Dark { get; } = new()
    {
        Kind = HexCraftThemeKind.Dark,
        WindowBg = "#111318",
        ToolbarBg = "#1B1F27",
        ToolbarBorder = "#2C323F",
        PaneBg = "#181B22",
        PaneHeaderBg = "#202530",
        PaneBorder = "#282E3B",
        EditorBg = "#14171D",
        EditorHeaderBg = "#1C2029",
        EditorGutterBg = "#181B22",
        EditorGridLine = "#282E3B",
        ConsoleBg = "#101217",
        CardBg = "#212836",
        RowBg = "#1B202B",
        ButtonBg = "#252B37",
        ActiveTabBg = "#2B3240",
        InactiveTabBg = "#1B1F27",

        PrimaryText = "#D7DAE0",
        SecondaryText = "#ABB2BF",
        MutedText = "#7F848E",
        NullByteText = "#4B5263",
        AddressText = "#56B6C2",
        AsciiText = "#98C379",
        ModifiedByteText = "#E06C75",

        AccentBlue = "#61AFEF",
        AccentCyan = "#56B6C2",
        AccentGreen = "#98C379",
        AccentGold = "#E5C07B",
        AccentPurple = "#C678DD",
        AccentRed = "#E06C75",
        SelectionFill = "#3D61AFEF",
        CursorFill = "#E5C07B"
    };

    public static HexCraftThemePalette Light { get; } = new()
    {
        Kind = HexCraftThemeKind.Light,
        WindowBg = "#F3F5F8",
        ToolbarBg = "#E8ECF2",
        ToolbarBorder = "#CBD2DF",
        PaneBg = "#FFFFFF",
        PaneHeaderBg = "#E4E9F2",
        PaneBorder = "#CBD2DF",
        EditorBg = "#FFFFFF",
        EditorHeaderBg = "#EEF1F6",
        EditorGutterBg = "#F5F7FA",
        EditorGridLine = "#D5DCE6",
        ConsoleBg = "#F7F9FC",
        CardBg = "#EEF2F8",
        RowBg = "#F2F5FA",
        ButtonBg = "#FFFFFF",
        ActiveTabBg = "#FFFFFF",
        InactiveTabBg = "#E2E7F0",

        PrimaryText = "#1E2430",
        SecondaryText = "#3B4454",
        MutedText = "#636E82",
        NullByteText = "#A6B0C2",
        AddressText = "#0969DA",
        AsciiText = "#1A7F37",
        ModifiedByteText = "#CF222E",

        AccentBlue = "#0969DA",
        AccentCyan = "#0550AE",
        AccentGreen = "#1A7F37",
        AccentGold = "#9A6700",
        AccentPurple = "#8250DF",
        AccentRed = "#CF222E",
        SelectionFill = "#380969DA",
        CursorFill = "#D97706"
    };

    public static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));
}
