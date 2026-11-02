using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using HexCraft.App.Controls;
using HexCraft.Core.Analysis;
using HexCraft.Core.Buffers;
using HexCraft.Templates;
using HexCraft.Templates.Evaluation;
using HexCraft.Tools;

namespace HexCraft.App;

/// <summary>
/// Main multi-window workspace for HexCraft on Windows 11 & Linux.
/// Supports Dark and Light themes and hosts:
///   a) Multi-Tab Primary Hex + ASCII Editor (Center)
///   b) Data Inspector, Selection Byte Transforms & Copy-As-Code (Right Top)
///   c) File Information, Magic Identification, Exif Metadata, Hashes & Block Entropy Chart (Right Bottom)
///   d) 010 Editor Binary Template (.bt) Results Tree & Live Script Editor (Bottom Tab 1)
///   e) Strings Viewer with Regex/Search filter (Bottom Tab 2)
///   f) Binwalk & unsquashfs Firmware Analyzer + Built-in GZip/ZIP Unpacker (Bottom Tab 3)
///   g) Bookmarks & Annotations Manager (Bottom Tab 4)
/// </summary>
public sealed class MainWindow : Window
{
    private readonly List<BinaryDocument> _openDocuments = new();
    private int _activeDocIndex;
    private BinaryDocument _document => _openDocuments[_activeDocIndex];

    private HexCraftThemePalette _theme = HexCraftThemePalette.Dark;
    private readonly ComboBox _themeSelectorCombo;

    private readonly StackPanel _documentTabsStrip;
    private readonly HexEditorControl _hexEditor;
    private readonly IReadOnlyList<BinaryTemplateDefinition> _templates;
    private List<ExtractedString> _allStrings = new();
    private List<FirmwareSignatureEntry> _firmwareSignatures = new();

    // Status & Header Controls
    private readonly TextBlock _statusOffsetLabel;
    private readonly TextBlock _statusSelectionLabel;
    private readonly TextBlock _statusSizeLabel;
    private readonly TextBlock _statusToolSummaryLabel;

    // Right Pane Controls
    private readonly CheckBox _bigEndianCheck;
    private readonly StackPanel _inspectorListPanel;
    private readonly StackPanel _fileMetadataPanel;

    // Template Pane Controls
    private readonly ComboBox _templateCombo;
    private readonly TextBox _templateEditorBox;
    private readonly TreeView _templateTree;
    private readonly TextBox _templateConsoleBox;

    // Strings Pane Controls
    private readonly TextBox _stringsSearchBox;
    private readonly CheckBox _stringsRegexCheck;
    private readonly NumericUpDown _stringsMinLenInput;
    private readonly ListBox _stringsListBox;
    private readonly TextBlock _stringsCountLabel;

    // Binwalk / Firmware Pane Controls
    private readonly ListBox _binwalkListBox;
    private readonly ListBox _extractedFilesListBox;
    private readonly TextBox _toolLogBox;

    // Bookmarks & Byte Ops Controls
    private readonly TextBox _bookmarkNameBox;
    private readonly ComboBox _bookmarkColorCombo;
    private readonly ListBox _bookmarksListBox;
    private readonly TextBox _xorKeyBox;
    private readonly ComboBox _copyFormatCombo;

    // Top Navigation / Search Controls
    private readonly TextBox _gotoOffsetBox;
    private readonly TextBox _searchBox;
    private readonly ComboBox _searchModeCombo;

    // Themeable structural containers
    private Border? _topToolbarBorder;
    private Border? _docTabBarBorder;
    private TabControl? _bottomDockTabControl;
    private Border? _statusBarBorder;
    private readonly List<(Border Outer, Border Header, TextBlock Title)> _titledPanes = new();
    private readonly List<GridSplitter> _splitters = new();
    private readonly List<TextBlock> _toolbarLabels = new();
    private readonly List<(Button Button, string AccentRole)> _themedButtons = new();

    private static readonly (string Label, string Hex)[] BookmarkColors =
    {
        ("Gold (#E5C07B)", "#E5C07B"),
        ("Cyan (#56B6C2)", "#56B6C2"),
        ("Green (#98C379)", "#98C379"),
        ("Purple (#C678DD)", "#C678DD"),
        ("Coral (#E06C75)", "#E06C75"),
        ("Blue (#61AFEF)", "#61AFEF")
    };

    public MainWindow()
    {
        Title = "HexCraft v1.0 — Cross-Platform Reverse Engineering Hex Editor";
        Width = 1520;
        Height = 940;
        MinWidth = 1060;
        MinHeight = 700;
        Background = HexCraftThemePalette.Brush(_theme.WindowBg);
        TransparencyLevelHint = new[]
        {
            WindowTransparencyLevel.Mica,
            WindowTransparencyLevel.AcrylicBlur,
            WindowTransparencyLevel.None
        };

        _templates = TemplateRepository.GetAvailableTemplates();

        // Start with a clean 256-byte blank buffer ready for editing or opening any file
        var initialDoc = new BinaryDocument(new byte[256], "Untitled.bin");
        _openDocuments.Add(initialDoc);
        _activeDocIndex = 0;

        _themeSelectorCombo = new ComboBox
        {
            Width = 115,
            ItemsSource = new[] { "Dark Theme", "Light Theme" },
            SelectedIndex = 0
        };

        _documentTabsStrip = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 4,
            Margin = new Thickness(4, 2)
        };

        _hexEditor = new HexEditorControl
        {
            Document = _document,
            Palette = _theme
        };

        _statusOffsetLabel = CreateStatusText("Offset: 0x00000000 (0)");
        _statusSelectionLabel = CreateStatusText("Selection: 1 B");
        _statusSizeLabel = CreateStatusText("Size: 0 B");
        _statusToolSummaryLabel = CreateStatusText("");

        _bigEndianCheck = new CheckBox
        {
            Content = "Big Endian",
            Margin = new Thickness(4, 0)
        };
        _bigEndianCheck.IsCheckedChanged += (_, _) => RefreshDataInspector(_hexEditor.CursorOffset);

        _inspectorListPanel = new StackPanel { Spacing = 2 };
        _fileMetadataPanel = new StackPanel { Spacing = 4 };

        _templateCombo = new ComboBox
        {
            Width = 230,
            ItemsSource = _templates.Select(t => t.DisplayName).ToList(),
            SelectedIndex = 0
        };
        _templateEditorBox = new TextBox
        {
            AcceptsReturn = true,
            AcceptsTab = true,
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 12,
            TextWrapping = TextWrapping.NoWrap
        };
        _templateTree = new TreeView();
        _templateConsoleBox = new TextBox
        {
            IsReadOnly = true,
            AcceptsReturn = true,
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 11.5
        };

        _stringsSearchBox = new TextBox { Width = 220, Watermark = "Filter strings or regex..." };
        _stringsRegexCheck = new CheckBox { Content = "Regex" };
        _stringsMinLenInput = new NumericUpDown { Minimum = 2, Maximum = 64, Value = 4, Width = 110 };
        _stringsListBox = new ListBox();
        _stringsCountLabel = new TextBlock
        {
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0)
        };

        _binwalkListBox = new ListBox();
        _extractedFilesListBox = new ListBox();
        _toolLogBox = new TextBox
        {
            IsReadOnly = true,
            AcceptsReturn = true,
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 11.5
        };

        _bookmarkNameBox = new TextBox { Width = 180, Watermark = "Bookmark label..." };
        _bookmarkColorCombo = new ComboBox
        {
            Width = 150,
            ItemsSource = BookmarkColors.Select(c => c.Label).ToList(),
            SelectedIndex = 0
        };
        _bookmarksListBox = new ListBox();

        _xorKeyBox = new TextBox { Width = 75, Text = "0xFF", Watermark = "0xFF" };
        _copyFormatCombo = new ComboBox
        {
            Width = 135,
            ItemsSource = new[]
            {
                "Hex Bytes",
                "C uint8_t[]",
                "C# byte[]",
                "Python b'...'",
                "Base64"
            },
            SelectedIndex = 1
        };

        _gotoOffsetBox = new TextBox { Width = 105, Watermark = "0x180 or 384" };
        _searchBox = new TextBox { Width = 165, Watermark = "ASCII or Hex (89 50)..." };
        _searchModeCombo = new ComboBox
        {
            ItemsSource = new[] { "ASCII Text", "Hex Bytes" },
            SelectedIndex = 0,
            Width = 110
        };

        Content = BuildWorkspaceLayout();
        WireEvents();
        ApplyTheme(HexCraftThemePalette.Dark);
    }

    public void ApplyTheme(HexCraftThemePalette palette)
    {
        _theme = palette;
        if (Application.Current is not null)
        {
            Application.Current.RequestedThemeVariant =
                palette.Kind == HexCraftThemeKind.Dark ? ThemeVariant.Dark : ThemeVariant.Light;
        }

        Background = HexCraftThemePalette.Brush(_theme.WindowBg);
        _hexEditor.Palette = _theme;

        if (_topToolbarBorder is not null)
        {
            _topToolbarBorder.Background = HexCraftThemePalette.Brush(_theme.ToolbarBg);
            _topToolbarBorder.BorderBrush = HexCraftThemePalette.Brush(_theme.ToolbarBorder);
        }

        if (_docTabBarBorder is not null)
        {
            _docTabBarBorder.Background = HexCraftThemePalette.Brush(_theme.PaneBg);
            _docTabBarBorder.BorderBrush = HexCraftThemePalette.Brush(_theme.PaneBorder);
        }

        if (_bottomDockTabControl is not null)
        {
            _bottomDockTabControl.Background = HexCraftThemePalette.Brush(_theme.PaneBg);
        }

        if (_statusBarBorder is not null)
        {
            _statusBarBorder.Background = HexCraftThemePalette.Brush(_theme.PaneBg);
            _statusBarBorder.BorderBrush = HexCraftThemePalette.Brush(_theme.PaneBorder);
        }

        foreach (var (outer, header, title) in _titledPanes)
        {
            outer.Background = HexCraftThemePalette.Brush(_theme.PaneBg);
            outer.BorderBrush = HexCraftThemePalette.Brush(_theme.PaneBorder);
            header.Background = HexCraftThemePalette.Brush(_theme.PaneHeaderBg);
            title.Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText);
        }

        foreach (var splitter in _splitters)
        {
            splitter.Background = HexCraftThemePalette.Brush(_theme.PaneBorder);
        }

        foreach (var lbl in _toolbarLabels)
        {
            lbl.Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText);
        }

        foreach (var (btn, role) in _themedButtons)
        {
            string accent = ResolveAccentHex(role);
            btn.Background = HexCraftThemePalette.Brush(_theme.ButtonBg);
            btn.Foreground = HexCraftThemePalette.Brush(accent);
            btn.BorderBrush = HexCraftThemePalette.Brush(accent);
        }

        _templateEditorBox.Background = HexCraftThemePalette.Brush(_theme.EditorBg);
        _templateEditorBox.Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText);
        _templateTree.Background = HexCraftThemePalette.Brush(_theme.EditorBg);
        _templateTree.Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText);
        _templateConsoleBox.Background = HexCraftThemePalette.Brush(_theme.ConsoleBg);
        _templateConsoleBox.Foreground = HexCraftThemePalette.Brush(_theme.AccentGreen);

        _stringsListBox.Background = HexCraftThemePalette.Brush(_theme.EditorBg);
        _stringsListBox.Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText);
        _stringsCountLabel.Foreground = HexCraftThemePalette.Brush(_theme.AccentGreen);

        _binwalkListBox.Background = HexCraftThemePalette.Brush(_theme.EditorBg);
        _binwalkListBox.Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText);
        _extractedFilesListBox.Background = HexCraftThemePalette.Brush(_theme.EditorBg);
        _extractedFilesListBox.Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText);
        _toolLogBox.Background = HexCraftThemePalette.Brush(_theme.ConsoleBg);
        _toolLogBox.Foreground = HexCraftThemePalette.Brush(_theme.AccentGold);

        _bookmarksListBox.Background = HexCraftThemePalette.Brush(_theme.EditorBg);
        _bookmarksListBox.Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText);

        _statusOffsetLabel.Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText);
        _statusSelectionLabel.Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText);
        _statusSizeLabel.Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText);
        _statusToolSummaryLabel.Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText);

        RefreshDocumentTabsStrip();
        RefreshAllPanesForCurrentDocument();
    }

    private string ResolveAccentHex(string role)
    {
        return role switch
        {
            "blue" => _theme.AccentBlue,
            "cyan" => _theme.AccentCyan,
            "green" => _theme.AccentGreen,
            "gold" => _theme.AccentGold,
            "purple" => _theme.AccentPurple,
            "red" => _theme.AccentRed,
            _ => _theme.SecondaryText
        };
    }

    private Control BuildWorkspaceLayout()
    {
        var rootGrid = new Grid
        {
            RowDefinitions = new RowDefinitions("Auto,*,Auto")
        };

        // 1. Top Command & Transformation Bar
        rootGrid.Children.Add(BuildTopToolbar());

        // 2. Main Multi-Window Split Area
        var mainHorizontalGrid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("*,5,400"),
            Margin = new Thickness(6, 4, 6, 4)
        };
        Grid.SetRow(mainHorizontalGrid, 1);

        // Left/Center vertical split: Multi-Tab Document Bar + Primary Hex View (top) + Docked Analysis Windows (bottom)
        var centerVerticalGrid = new Grid
        {
            RowDefinitions = new RowDefinitions("Auto,*,5,315")
        };

        _docTabBarBorder = new Border
        {
            BorderThickness = new Thickness(1, 1, 1, 0),
            CornerRadius = new CornerRadius(5, 5, 0, 0),
            Padding = new Thickness(4, 2),
            Child = _documentTabsStrip
        };
        Grid.SetRow(_docTabBarBorder, 0);
        centerVerticalGrid.Children.Add(_docTabBarBorder);

        var hexPanel = CreateTitledPane(
            "PRIMARY VIEW — HEX / ASCII EDITOR (Type Hex or Tab to edit ASCII | Drag to Select | Right Edge: Color/Bookmark Minimap)",
            _hexEditor);
        Grid.SetRow(hexPanel, 1);
        centerVerticalGrid.Children.Add(hexPanel);

        var vSplitter = CreateSplitter(GridResizeDirection.Rows);
        Grid.SetRow(vSplitter, 2);
        centerVerticalGrid.Children.Add(vSplitter);

        var bottomDockTabs = BuildBottomDockedWindows();
        Grid.SetRow(bottomDockTabs, 3);
        centerVerticalGrid.Children.Add(bottomDockTabs);

        Grid.SetColumn(centerVerticalGrid, 0);
        mainHorizontalGrid.Children.Add(centerVerticalGrid);

        var hSplitter = CreateSplitter(GridResizeDirection.Columns);
        Grid.SetColumn(hSplitter, 1);
        mainHorizontalGrid.Children.Add(hSplitter);

        // Right Dock: Data Inspector (top) + File Information & Metadata (bottom)
        var rightSideDock = BuildRightSideDockedWindows();
        Grid.SetColumn(rightSideDock, 2);
        mainHorizontalGrid.Children.Add(rightSideDock);

        rootGrid.Children.Add(mainHorizontalGrid);

        // 3. Status Bar
        var statusBar = BuildStatusBar();
        Grid.SetRow(statusBar, 2);
        rootGrid.Children.Add(statusBar);

        return rootGrid;
    }

    private Control BuildTopToolbar()
    {
        _topToolbarBorder = new Border
        {
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(8, 6)
        };

        var outerStack = new StackPanel { Spacing = 5 };

        // Row 1: File, Undo/Redo, GoTo, Find, Theme Switcher
        var row1 = new WrapPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center
        };

        row1.Children.Add(CreateActionButton("Open File...", "blue", OnOpenFileClicked));
        row1.Children.Add(CreateActionButton("Save", "green", OnSaveFileClicked));
        row1.Children.Add(CreateActionButton("New Blank Buffer", "purple", (_, _) => AddNewBlankTab()));
        row1.Children.Add(CreateActionButton("Undo", "neutral", (_, _) => { _document.Undo(); OnDocumentEdited(); }));
        row1.Children.Add(CreateActionButton("Redo", "neutral", (_, _) => { _document.Redo(); OnDocumentEdited(); }));

        row1.Children.Add(CreateToolbarLabel("Offset:", new Thickness(12, 0, 4, 0)));
        row1.Children.Add(_gotoOffsetBox);
        row1.Children.Add(CreateActionButton("Go", "cyan", (_, _) => ExecuteGotoOffset()));

        row1.Children.Add(CreateToolbarLabel("Find:", new Thickness(12, 0, 4, 0)));
        row1.Children.Add(_searchModeCombo);
        row1.Children.Add(_searchBox);
        row1.Children.Add(CreateActionButton("Find Next", "gold", (_, _) => ExecuteFindNext()));

        row1.Children.Add(CreateToolbarLabel("Theme:", new Thickness(14, 0, 4, 0)));
        row1.Children.Add(_themeSelectorCombo);

        // Row 2: Selection Byte Operations & Copy-As-Code
        var row2 = new WrapPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center
        };

        row2.Children.Add(CreateToolbarLabel("Selection Ops:", new Thickness(2, 0, 6, 0), bold: true));
        row2.Children.Add(_xorKeyBox);
        row2.Children.Add(CreateActionButton("XOR Selection", "gold", (_, _) => ExecuteXorSelection()));
        row2.Children.Add(CreateActionButton("Invert (~NOT)", "cyan", (_, _) => ExecuteInvertSelection()));
        row2.Children.Add(CreateActionButton("Zero-Fill (0x00)", "red", (_, _) => ExecuteFillSelection(0x00)));
        row2.Children.Add(CreateActionButton("Reverse Bytes", "purple", (_, _) => ExecuteReverseSelection()));

        row2.Children.Add(CreateToolbarLabel("Copy Selection As:", new Thickness(14, 0, 6, 0), bold: true));
        row2.Children.Add(_copyFormatCombo);
        row2.Children.Add(CreateActionButton("Copy to Clipboard", "green", OnCopySelectionAsCodeClicked));

        outerStack.Children.Add(row1);
        outerStack.Children.Add(row2);
        _topToolbarBorder.Child = outerStack;
        return _topToolbarBorder;
    }

    private Control BuildBottomDockedWindows()
    {
        _bottomDockTabControl = new TabControl
        {
            Padding = new Thickness(4)
        };

        // Tab 1: 010 Binary Template (.bt) Results & Live Script Runner
        var templateGrid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("1.25*,5,1*")
        };

        var resultsPane = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        var tplHeaderBar = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 6,
            Margin = new Thickness(4, 4)
        };
        tplHeaderBar.Children.Add(CreateToolbarLabel("Template:", new Thickness(0)));
        tplHeaderBar.Children.Add(_templateCombo);
        tplHeaderBar.Children.Add(CreateActionButton("Run Template (.bt)", "green", (_, _) => RunActiveTemplate()));
        tplHeaderBar.Children.Add(CreateActionButton("Load .bt File...", "blue", OnLoadBtFileClicked));
        tplHeaderBar.Children.Add(CreateActionButton("Clear Overlay", "red", (_, _) =>
        {
            _hexEditor.ColorIntervals = Array.Empty<ByteColorInterval>();
        }));

        Grid.SetRow(tplHeaderBar, 0);
        resultsPane.Children.Add(tplHeaderBar);
        Grid.SetRow(_templateTree, 1);
        resultsPane.Children.Add(_templateTree);

        Grid.SetColumn(resultsPane, 0);
        templateGrid.Children.Add(resultsPane);

        var tplSplitter = CreateSplitter(GridResizeDirection.Columns);
        Grid.SetColumn(tplSplitter, 1);
        templateGrid.Children.Add(tplSplitter);

        var scriptAndConsoleGrid = new Grid
        {
            RowDefinitions = new RowDefinitions("*,65")
        };
        Grid.SetRow(_templateEditorBox, 0);
        scriptAndConsoleGrid.Children.Add(_templateEditorBox);
        Grid.SetRow(_templateConsoleBox, 1);
        scriptAndConsoleGrid.Children.Add(_templateConsoleBox);

        Grid.SetColumn(scriptAndConsoleGrid, 2);
        templateGrid.Children.Add(scriptAndConsoleGrid);

        // Tab 2: Strings Viewer
        var stringsGrid = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        var stringsToolbar = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            Margin = new Thickness(4, 4)
        };
        stringsToolbar.Children.Add(CreateToolbarLabel("Filter:", new Thickness(0)));
        stringsToolbar.Children.Add(_stringsSearchBox);
        stringsToolbar.Children.Add(_stringsRegexCheck);
        stringsToolbar.Children.Add(CreateToolbarLabel("Min Len:", new Thickness(0)));
        stringsToolbar.Children.Add(_stringsMinLenInput);
        stringsToolbar.Children.Add(CreateActionButton("Rescan Strings", "blue", (_, _) => RefreshStringsPane()));
        stringsToolbar.Children.Add(_stringsCountLabel);

        Grid.SetRow(stringsToolbar, 0);
        stringsGrid.Children.Add(stringsToolbar);
        Grid.SetRow(_stringsListBox, 1);
        stringsGrid.Children.Add(_stringsListBox);

        // Tab 3: HexCraft Internal Signature Engine & Unsquashfs Integration
        var binwalkGrid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("1.3*,5,1*")
        };

        var leftScanGrid = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        var bwToolbar = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 6,
            Margin = new Thickness(4, 4)
        };
        bwToolbar.Children.Add(CreateActionButton("Run Signature Scan", "blue", (_, _) => RefreshBinwalkScan(tryExternal: false)));
        bwToolbar.Children.Add(CreateActionButton("Carve / Unpack Selected (unsquashfs / GZip / ZIP)", "green", OnCarveOrUnsquashClicked));
        bwToolbar.Children.Add(CreateActionButton("Open Extracted File in New Tab", "purple", OnOpenExtractedFileClicked));

        Grid.SetRow(bwToolbar, 0);
        leftScanGrid.Children.Add(bwToolbar);
        Grid.SetRow(_binwalkListBox, 1);
        leftScanGrid.Children.Add(_binwalkListBox);

        Grid.SetColumn(leftScanGrid, 0);
        binwalkGrid.Children.Add(leftScanGrid);

        var bwSplitter = CreateSplitter(GridResizeDirection.Columns);
        Grid.SetColumn(bwSplitter, 1);
        binwalkGrid.Children.Add(bwSplitter);

        var rightExtractGrid = new Grid { RowDefinitions = new RowDefinitions("Auto,*,85") };
        rightExtractGrid.Children.Add(CreateToolbarLabel(
            "Extracted / Decompressed Files (Double-click to open in new HexCraft tab):",
            new Thickness(4, 4)));
        Grid.SetRow(_extractedFilesListBox, 1);
        rightExtractGrid.Children.Add(_extractedFilesListBox);
        Grid.SetRow(_toolLogBox, 2);
        rightExtractGrid.Children.Add(_toolLogBox);

        Grid.SetColumn(rightExtractGrid, 2);
        binwalkGrid.Children.Add(rightExtractGrid);

        // Tab 4: Bookmarks & Annotations Manager
        var bookmarksGrid = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        var bmToolbar = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            Margin = new Thickness(4, 4)
        };
        bmToolbar.Children.Add(CreateToolbarLabel("Bookmark Label:", new Thickness(0)));
        bmToolbar.Children.Add(_bookmarkNameBox);
        bmToolbar.Children.Add(_bookmarkColorCombo);
        bmToolbar.Children.Add(CreateActionButton("Bookmark Current Selection", "green", (_, _) => AddBookmarkFromSelection()));
        bmToolbar.Children.Add(CreateActionButton("Remove Selected Bookmark", "red", (_, _) => RemoveSelectedBookmark()));

        Grid.SetRow(bmToolbar, 0);
        bookmarksGrid.Children.Add(bmToolbar);
        Grid.SetRow(_bookmarksListBox, 1);
        bookmarksGrid.Children.Add(_bookmarksListBox);

        _bottomDockTabControl.ItemsSource = new[]
        {
            new TabItem
            {
                Header = "010 Binary Templates (.bt)",
                Content = templateGrid
            },
            new TabItem
            {
                Header = "Strings Viewer",
                Content = stringsGrid
            },
            new TabItem
            {
                Header = $"Firmware Signatures ({FirmwareToolService.DefaultRegistry.Parsers.Count} Parsers) & Unpack",
                Content = binwalkGrid
            },
            new TabItem
            {
                Header = "Bookmarks & Annotations",
                Content = bookmarksGrid
            }
        };

        return _bottomDockTabControl;
    }

    private Control BuildRightSideDockedWindows()
    {
        var rightGrid = new Grid
        {
            RowDefinitions = new RowDefinitions("1.05*,5,1.15*")
        };

        // Top Pane: Data Inspector
        var inspectorHeader = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
        DockPanel.SetDock(_bigEndianCheck, Dock.Right);
        inspectorHeader.Children.Add(_bigEndianCheck);

        var inspectorScroll = new ScrollViewer
        {
            Content = _inspectorListPanel,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        var inspectorContainer = new DockPanel();
        DockPanel.SetDock(inspectorHeader, Dock.Top);
        inspectorContainer.Children.Add(inspectorHeader);
        inspectorContainer.Children.Add(inspectorScroll);

        var inspectorPane = CreateTitledPane("DATA INSPECTOR (LIVE CURSOR DECODER)", inspectorContainer);
        Grid.SetRow(inspectorPane, 0);
        rightGrid.Children.Add(inspectorPane);

        var rSplitter = CreateSplitter(GridResizeDirection.Rows);
        Grid.SetRow(rSplitter, 1);
        rightGrid.Children.Add(rSplitter);

        // Bottom Pane: File Information, Identification, Exif, Hashes & Entropy
        var metaScroll = new ScrollViewer
        {
            Content = _fileMetadataPanel,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        var metaPane = CreateTitledPane("FILE INFORMATION, MAGIC ID, EXIF & ENTROPY", metaScroll);
        Grid.SetRow(metaPane, 2);
        rightGrid.Children.Add(metaPane);

        return rightGrid;
    }

    private Control BuildStatusBar()
    {
        _statusBarBorder = new Border
        {
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(10, 4)
        };

        var stack = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 20
        };
        stack.Children.Add(_statusOffsetLabel);
        stack.Children.Add(_statusSelectionLabel);
        stack.Children.Add(_statusSizeLabel);
        stack.Children.Add(_statusToolSummaryLabel);

        _statusBarBorder.Child = stack;
        return _statusBarBorder;
    }

    private void WireEvents()
    {
        _themeSelectorCombo.SelectionChanged += (_, _) =>
        {
            var chosen = _themeSelectorCombo.SelectedIndex == 1
                ? HexCraftThemePalette.Light
                : HexCraftThemePalette.Dark;
            ApplyTheme(chosen);
        };

        _hexEditor.CursorChanged += (_, e) =>
        {
            _statusOffsetLabel.Text = $"Offset: 0x{e.Offset:X8} ({e.Offset:N0})";
            _statusSelectionLabel.Text = $"Selection: 0x{e.SelectionStart:X8} ({e.SelectionLength:N0} B)";
            RefreshDataInspector(e.Offset);
        };

        _hexEditor.BytesModified += (_, _) => OnDocumentEdited();

        _templateCombo.SelectionChanged += (_, _) =>
        {
            int idx = _templateCombo.SelectedIndex;
            if (idx >= 0 && idx < _templates.Count)
            {
                _templateEditorBox.Text = _templates[idx].SourceCode;
                RunActiveTemplate();
            }
        };

        _templateTree.SelectionChanged += (_, _) =>
        {
            if (_templateTree.SelectedItem is TreeViewItem tvi && tvi.Tag is TemplateResultNode node && node.ByteLength > 0)
            {
                _hexEditor.SelectRange(node.StartOffset, node.ByteLength);
            }
        };

        _stringsSearchBox.TextChanged += (_, _) => FilterStringsView();
        _stringsRegexCheck.IsCheckedChanged += (_, _) => FilterStringsView();
        _stringsListBox.SelectionChanged += (_, _) =>
        {
            if (_stringsListBox.SelectedItem is ListBoxItem item && item.Tag is ExtractedString str)
            {
                _hexEditor.SelectRange(str.Offset, str.ByteLength);
            }
        };

        _binwalkListBox.SelectionChanged += (_, _) =>
        {
            if (_binwalkListBox.SelectedItem is ListBoxItem item && item.Tag is FirmwareSignatureEntry sig)
            {
                _hexEditor.SelectRange(sig.Offset, Math.Max(16, Math.Min(sig.EstimatedSize, 256)));
            }
        };

        _bookmarksListBox.SelectionChanged += (_, _) =>
        {
            if (_bookmarksListBox.SelectedItem is ListBoxItem item && item.Tag is Bookmark bm)
            {
                _hexEditor.SelectRange(bm.Offset, bm.Length);
            }
        };

        _extractedFilesListBox.DoubleTapped += OnOpenExtractedFileClicked;
    }

    private void RefreshDocumentTabsStrip()
    {
        _documentTabsStrip.Children.Clear();
        for (int i = 0; i < _openDocuments.Count; i++)
        {
            int tabIdx = i;
            var doc = _openDocuments[i];
            bool isActive = i == _activeDocIndex;
            string label = doc.IsModified ? $"{doc.DisplayName} *" : doc.DisplayName;

            var tabBtn = new Button
            {
                Content = label,
                Background = HexCraftThemePalette.Brush(isActive ? _theme.ActiveTabBg : _theme.InactiveTabBg),
                Foreground = HexCraftThemePalette.Brush(isActive ? _theme.AccentBlue : _theme.SecondaryText),
                BorderBrush = HexCraftThemePalette.Brush(isActive ? _theme.AccentBlue : _theme.PaneBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 3),
                FontSize = 11.5,
                FontWeight = isActive ? FontWeight.Bold : FontWeight.Normal
            };
            tabBtn.Click += (_, _) => SwitchToDocumentTab(tabIdx);
            _documentTabsStrip.Children.Add(tabBtn);

            if (_openDocuments.Count > 1)
            {
                var closeBtn = new Button
                {
                    Content = "×",
                    Background = Brushes.Transparent,
                    Foreground = HexCraftThemePalette.Brush(_theme.MutedText),
                    Padding = new Thickness(4, 2),
                    FontSize = 11
                };
                closeBtn.Click += (_, _) => CloseDocumentTab(tabIdx);
                _documentTabsStrip.Children.Add(closeBtn);
            }
        }
    }

    private void SwitchToDocumentTab(int index)
    {
        if (index < 0 || index >= _openDocuments.Count) return;
        _activeDocIndex = index;
        _hexEditor.Document = _document;
        RefreshDocumentTabsStrip();
        RefreshAllPanesForCurrentDocument();
    }

    private void CloseDocumentTab(int index)
    {
        if (_openDocuments.Count <= 1 || index < 0 || index >= _openDocuments.Count)
            return;

        var doc = _openDocuments[index];
        _openDocuments.RemoveAt(index);
        doc.Dispose();

        if (_activeDocIndex >= _openDocuments.Count)
            _activeDocIndex = _openDocuments.Count - 1;

        _hexEditor.Document = _document;
        RefreshDocumentTabsStrip();
        RefreshAllPanesForCurrentDocument();
    }

    private void RefreshAllPanesForCurrentDocument()
    {
        var toolStatus = FirmwareToolService.DetectInstalledTools();
        _statusToolSummaryLabel.Text = toolStatus.Summary;
        _statusSizeLabel.Text = $"Size: {FileAnalyzer.FormatBytes(_document.Length)}";

        RefreshDataInspector(_hexEditor.CursorOffset);
        RefreshFileMetadataPane();
        RefreshStringsPane();
        RefreshBinwalkScan(tryExternal: false);
        RefreshBookmarksPane();

        if (_templates.Count > 0 && string.IsNullOrEmpty(_templateEditorBox.Text))
        {
            _templateEditorBox.Text = _templates[0].SourceCode;
        }
        RunActiveTemplate();
    }

    private void OnDocumentEdited()
    {
        RefreshDocumentTabsStrip();
        _statusSizeLabel.Text = $"Size: {FileAnalyzer.FormatBytes(_document.Length)}";
        RefreshDataInspector(_hexEditor.CursorOffset);
        RefreshFileMetadataPane();
        _hexEditor.InvalidateVisual();
    }

    private void RefreshDataInspector(long offset)
    {
        _inspectorListPanel.Children.Clear();
        bool bigEndian = _bigEndianCheck.IsChecked == true;
        var entries = DataInspectorDecoder.DecodeAt(_document, offset, bigEndian);

        foreach (var entry in entries)
        {
            var row = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("125,*"),
                Margin = new Thickness(2, 1)
            };

            var nameTxt = new TextBlock
            {
                Text = entry.TypeName,
                Foreground = HexCraftThemePalette.Brush(_theme.AccentBlue),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11.5
            };
            var valTxt = new SelectableTextBlock
            {
                Text = entry.ValueText,
                Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11.5
            };

            Grid.SetColumn(nameTxt, 0);
            Grid.SetColumn(valTxt, 1);
            row.Children.Add(nameTxt);
            row.Children.Add(valTxt);
            _inspectorListPanel.Children.Add(row);
        }
    }

    private void RefreshFileMetadataPane()
    {
        _fileMetadataPanel.Children.Clear();
        var report = FileAnalyzer.Analyze(_document, entropyBlockCount: 32);

        AddMetadataSectionHeader("IDENTIFIED FORMATS (MAGIC SIGNATURES)");
        foreach (var match in report.MagicMatches)
        {
            var badge = new Border
            {
                Background = HexCraftThemePalette.Brush(_theme.CardBg),
                BorderBrush = HexCraftThemePalette.Brush(_theme.PaneBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 4),
                Margin = new Thickness(0, 2)
            };
            var sp = new StackPanel { Spacing = 2 };
            sp.Children.Add(new TextBlock
            {
                Text = $"{match.FormatName} [{match.Category}]",
                Foreground = HexCraftThemePalette.Brush(_theme.AccentGreen),
                FontWeight = FontWeight.Bold,
                FontSize = 12
            });
            sp.Children.Add(new TextBlock
            {
                Text = $"MIME: {match.MimeType} | Ext: {match.Extension} | Details: {match.Details}",
                Foreground = HexCraftThemePalette.Brush(_theme.SecondaryText),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            });

            if (!string.IsNullOrEmpty(match.RecommendedTemplate))
            {
                string recTpl = match.RecommendedTemplate;
                var applyBtn = CreateActionButton($"Apply {recTpl} Template", "purple", (_, _) =>
                {
                    int idx = _templates
                        .Select((t, i) => (t, i))
                        .FirstOrDefault(x => x.t.FileName.Equals(recTpl, StringComparison.OrdinalIgnoreCase)).i;
                    _templateCombo.SelectedIndex = idx;
                });
                applyBtn.Margin = new Thickness(0, 3, 0, 0);
                sp.Children.Add(applyBtn);
            }

            badge.Child = sp;
            _fileMetadataPanel.Children.Add(badge);
        }

        if (report.ExifAndFormatTags.Count > 0)
        {
            AddMetadataSectionHeader($"EXIF & FORMAT METADATA ({report.ExifAndFormatTags.Count} TAGS — CLICK TO JUMP)");
            foreach (var tag in report.ExifAndFormatTags)
            {
                AddExifTagRow(tag);
            }
        }

        AddMetadataSectionHeader("CRYPTOGRAPHIC HASHES & CHECKSUMS");
        AddMetadataKeyValue("File Size", report.FormattedSize);
        AddMetadataKeyValue("CRC-32", report.Crc32Hex);
        AddMetadataKeyValue("MD5", report.Md5Hex);
        AddMetadataKeyValue("SHA-1", report.Sha1Hex);
        AddMetadataKeyValue("SHA-256", report.Sha256Hex);

        AddMetadataSectionHeader("SHANNON ENTROPY & BLOCK DISTRIBUTION");
        AddMetadataKeyValue("Entropy", $"{report.OverallEntropy:F4} bits/byte");
        AddMetadataKeyValue("Assessment", report.EntropyAssessment);
        AddMetadataKeyValue("Printable ASCII", $"{report.PrintableAsciiPercent}%");
        AddMetadataKeyValue("Null Bytes (0x00)", $"{report.NullBytePercent}%");

        if (report.BlockEntropies.Length > 0)
        {
            var sparkPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 2,
                Height = 36,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 6, 0, 2)
            };
            double barWidth = Math.Max(4, 320.0 / report.BlockEntropies.Length);
            foreach (double be in report.BlockEntropies)
            {
                double h = Math.Max(3, (be / 8.0) * 34.0);
                string color = be >= 7.2 ? _theme.AccentRed : be >= 5.0 ? _theme.AccentGold : _theme.AccentCyan;
                sparkPanel.Children.Add(new Border
                {
                    Width = barWidth,
                    Height = h,
                    VerticalAlignment = VerticalAlignment.Bottom,
                    Background = HexCraftThemePalette.Brush(color),
                    CornerRadius = new CornerRadius(1)
                });
            }
            _fileMetadataPanel.Children.Add(sparkPanel);
        }
    }

    private void AddExifTagRow(MetadataTagEntry tag)
    {
        var rowBorder = new Border
        {
            Background = HexCraftThemePalette.Brush(_theme.RowBg),
            CornerRadius = new CornerRadius(3),
            Padding = new Thickness(5, 3),
            Margin = new Thickness(0, 1),
            Cursor = tag.SourceOffset.HasValue ? new Cursor(StandardCursorType.Hand) : null
        };

        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("145,*") };
        var keyText = new TextBlock
        {
            Text = $"[{tag.Group}] {tag.TagName}",
            Foreground = HexCraftThemePalette.Brush(_theme.AccentCyan),
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 11,
            TextTrimming = TextTrimming.CharacterEllipsis
        };

        string offsetHint = tag.SourceOffset.HasValue ? $" (@0x{tag.SourceOffset.Value:X})" : "";
        var valText = new SelectableTextBlock
        {
            Text = $"{tag.Value}{offsetHint}",
            Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText),
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap
        };

        Grid.SetColumn(keyText, 0);
        Grid.SetColumn(valText, 1);
        grid.Children.Add(keyText);
        grid.Children.Add(valText);
        rowBorder.Child = grid;

        if (tag.SourceOffset.HasValue)
        {
            long off = tag.SourceOffset.Value;
            int len = Math.Max(1, tag.SourceLength ?? 4);
            rowBorder.PointerPressed += (_, _) => _hexEditor.SelectRange(off, len);
        }

        _fileMetadataPanel.Children.Add(rowBorder);
    }

    private void AddMetadataSectionHeader(string title)
    {
        _fileMetadataPanel.Children.Add(new TextBlock
        {
            Text = title,
            Foreground = HexCraftThemePalette.Brush(_theme.AccentGold),
            FontWeight = FontWeight.Bold,
            FontSize = 11,
            Margin = new Thickness(0, 6, 0, 2)
        });
    }

    private void AddMetadataKeyValue(string key, string value)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("105,*") };
        var k = new TextBlock
        {
            Text = key + ":",
            Foreground = HexCraftThemePalette.Brush(_theme.MutedText),
            FontSize = 11.5
        };
        var v = new SelectableTextBlock
        {
            Text = value,
            Foreground = HexCraftThemePalette.Brush(_theme.PrimaryText),
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap
        };
        Grid.SetColumn(k, 0);
        Grid.SetColumn(v, 1);
        grid.Children.Add(k);
        grid.Children.Add(v);
        _fileMetadataPanel.Children.Add(grid);
    }

    private void RunActiveTemplate()
    {
        string code = _templateEditorBox.Text ?? "";
        var res = BtInterpreter.Execute(_document, code);

        _hexEditor.ColorIntervals = res.ColorIntervals;
        _templateTree.Items.Clear();

        foreach (var node in res.RootNodes)
        {
            _templateTree.Items.Add(CreateTemplateTreeItem(node));
        }

        var consoleLines = new List<string>(res.ConsoleOutput);
        if (res.Success)
        {
            consoleLines.Add($"[OK] Parsed {res.BytesParsed:N0} bytes ({res.RootNodes.Count} top-level structures, {res.ColorIntervals.Count} color intervals).");
        }
        else if (!string.IsNullOrEmpty(res.ErrorMessage))
        {
            consoleLines.Add($"[Error] {res.ErrorMessage}");
        }

        _templateConsoleBox.Text = string.Join(Environment.NewLine, consoleLines);
    }

    private TreeViewItem CreateTemplateTreeItem(TemplateResultNode node)
    {
        string commentPart = string.IsNullOrEmpty(node.Comment) ? "" : $"  // {node.Comment}";
        var item = new TreeViewItem
        {
            Header = $"{node.Name} ({node.TypeName}) = {node.DisplayValue}   [@ {node.OffsetHex}, {node.SizeText}]{commentPart}",
            IsExpanded = node.IsExpanded,
            Tag = node,
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 12
        };

        if (!string.IsNullOrEmpty(node.ColorHex) && Color.TryParse(node.ColorHex, out Color c))
        {
            if (_theme.Kind == HexCraftThemeKind.Light)
            {
                // Darken pastel template node text slightly on white background for crisp readability
                item.Foreground = new SolidColorBrush(Color.FromRgb(
                    (byte)(c.R * 0.65),
                    (byte)(c.G * 0.65),
                    (byte)(c.B * 0.65)));
            }
            else
            {
                item.Foreground = new SolidColorBrush(c);
            }
        }

        foreach (var child in node.Children)
        {
            item.Items.Add(CreateTemplateTreeItem(child));
        }

        return item;
    }

    private void RefreshStringsPane()
    {
        int minChars = (int)(_stringsMinLenInput.Value ?? 4);
        _allStrings = StringsScanner.Scan(_document, new StringScanOptions(MinCharacters: minChars, IncludeAscii: true, IncludeUtf16Le: true));
        FilterStringsView();
    }

    private void FilterStringsView()
    {
        var filtered = StringsScanner.Filter(_allStrings, _stringsSearchBox.Text, _stringsRegexCheck.IsChecked == true);
        _stringsListBox.Items.Clear();

        foreach (var s in filtered.Take(2000))
        {
            var item = new ListBoxItem
            {
                Content = $"{s.OffsetHex}  [{s.EncodingLabel,-10}] ({s.ByteLength,3} B)   {s.Value}",
                Tag = s,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 12
            };
            _stringsListBox.Items.Add(item);
        }

        _stringsCountLabel.Text = $"{filtered.Count:N0} strings found";
    }

    private void RefreshBinwalkScan(bool tryExternal)
    {
        _firmwareSignatures = FirmwareToolService.ScanSignatures(_document, tryExternalBinwalk: tryExternal);
        _binwalkListBox.Items.Clear();

        foreach (var sig in _firmwareSignatures)
        {
            var item = new ListBoxItem
            {
                Content = $"{sig.OffsetHex}  [{sig.SignatureType,-26}]  ({sig.SizeText})  —  {sig.Description}",
                Tag = sig,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 12
            };
            _binwalkListBox.Items.Add(item);
        }

        string parserNames = string.Join(", ", FirmwareToolService.DefaultRegistry.Parsers.Select(p => p.Name));
        _toolLogBox.Text = $"[HexCraft Internal Signature Engine ({FirmwareToolService.DefaultRegistry.Parsers.Count} Parsers: {parserNames})] Found {_firmwareSignatures.Count} validated embedded signatures.";
    }

    private void RefreshBookmarksPane()
    {
        _bookmarksListBox.Items.Clear();
        foreach (var bm in _document.Bookmarks)
        {
            var item = new ListBoxItem
            {
                Content = $"0x{bm.Offset:X8} ({bm.Length:N0} B)  —  {bm.Name}   [{bm.ColorHex}]  {bm.Comment}",
                Tag = bm,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 12
            };
            if (!string.IsNullOrEmpty(bm.ColorHex) && Color.TryParse(bm.ColorHex, out Color c))
            {
                item.Foreground = new SolidColorBrush(c);
            }
            _bookmarksListBox.Items.Add(item);
        }
    }

    private void AddBookmarkFromSelection()
    {
        var (start, len) = _hexEditor.GetSelectionRange();
        string name = string.IsNullOrWhiteSpace(_bookmarkNameBox.Text)
            ? $"Region_0x{start:X4}"
            : _bookmarkNameBox.Text.Trim();

        int colorIdx = Math.Clamp(_bookmarkColorCombo.SelectedIndex, 0, BookmarkColors.Length - 1);
        string colorHex = BookmarkColors[colorIdx].Hex;

        _document.Bookmarks.Add(new Bookmark(start, Math.Max(1, len), name, colorHex));
        _bookmarkNameBox.Text = "";
        RefreshBookmarksPane();
        _hexEditor.InvalidateVisual();
    }

    private void RemoveSelectedBookmark()
    {
        if (_bookmarksListBox.SelectedItem is ListBoxItem item && item.Tag is Bookmark bm)
        {
            _document.Bookmarks.Remove(bm);
            RefreshBookmarksPane();
            _hexEditor.InvalidateVisual();
        }
    }

    private void ExecuteXorSelection()
    {
        var (start, len) = _hexEditor.GetSelectionRange();
        string rawKey = (_xorKeyBox.Text ?? "0xFF").Trim();
        if (rawKey.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            rawKey = rawKey[2..];

        if (!byte.TryParse(rawKey, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte keyByte))
            keyByte = 0xFF;

        ByteOperations.XorRange(_document, start, len, new[] { keyByte });
        OnDocumentEdited();
    }

    private void ExecuteInvertSelection()
    {
        var (start, len) = _hexEditor.GetSelectionRange();
        ByteOperations.InvertRange(_document, start, len);
        OnDocumentEdited();
    }

    private void ExecuteFillSelection(byte fillValue)
    {
        var (start, len) = _hexEditor.GetSelectionRange();
        ByteOperations.FillRange(_document, start, len, fillValue);
        OnDocumentEdited();
    }

    private void ExecuteReverseSelection()
    {
        var (start, len) = _hexEditor.GetSelectionRange();
        ByteOperations.ReverseRange(_document, start, len);
        OnDocumentEdited();
    }

    private async void OnCopySelectionAsCodeClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var (start, len) = _hexEditor.GetSelectionRange();
        int cap = (int)Math.Min(len, 64 * 1024);
        byte[] selected = _document.ReadBytes(start, cap);

        var format = _copyFormatCombo.SelectedIndex switch
        {
            0 => CopyExportFormat.HexSpaceSeparated,
            1 => CopyExportFormat.CArray,
            2 => CopyExportFormat.CSharpArray,
            3 => CopyExportFormat.PythonBytes,
            4 => CopyExportFormat.Base64,
            _ => CopyExportFormat.CArray
        };

        string formatted = ByteOperations.FormatBytesAsCode(selected, format);
        if (Clipboard is not null)
        {
            await Clipboard.SetTextAsync(formatted);
        }
        _templateConsoleBox.Text = $"[Copied {selected.Length} bytes as {format}]{Environment.NewLine}{formatted}";
    }

    private async void OnCarveOrUnsquashClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        FirmwareSignatureEntry? selected = null;
        if (_binwalkListBox.SelectedItem is ListBoxItem item && item.Tag is FirmwareSignatureEntry sig)
            selected = sig;
        else if (_firmwareSignatures.Count > 0)
            selected = _firmwareSignatures[0];

        if (selected is null)
        {
            _toolLogBox.Text = "[!] Select a signature entry in the table first.";
            return;
        }

        var outcome = await FirmwareToolService.CarveAndExtractAsync(_document, selected);
        _toolLogBox.Text = outcome.LogOutput;
        _extractedFilesListBox.Items.Clear();

        foreach (string file in outcome.ExtractedFiles)
        {
            var fItem = new ListBoxItem
            {
                Content = $"{Path.GetFileName(file)}   ({new FileInfo(file).Length:N0} B)  [{file}]",
                Tag = file,
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11.5
            };
            _extractedFilesListBox.Items.Add(fItem);
        }
    }

    private void OnOpenExtractedFileClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (_extractedFilesListBox.SelectedItem is ListBoxItem item && item.Tag is string path && File.Exists(path))
        {
            OpenFileIntoNewTab(path);
        }
    }

    private async void OnOpenFileClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open Binary File in HexCraft",
            AllowMultiple = true
        });

        foreach (var file in files)
        {
            string? localPath = file.TryGetLocalPath();
            if (!string.IsNullOrEmpty(localPath) && File.Exists(localPath))
            {
                OpenFileIntoNewTab(localPath);
            }
        }
    }

    private async void OnSaveFileClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_document.FilePath) && File.Exists(_document.FilePath))
        {
            _document.Save(_document.FilePath);
            OnDocumentEdited();
            return;
        }

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save Binary File As",
            SuggestedFileName = _document.DisplayName
        });

        string? savePath = file?.TryGetLocalPath();
        if (!string.IsNullOrEmpty(savePath))
        {
            _document.Save(savePath);
            OnDocumentEdited();
        }
    }

    private async void OnLoadBtFileClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open 010 Editor Binary Template (.bt)",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("010 Binary Templates (*.bt)") { Patterns = new[] { "*.bt" } },
                FilePickerFileTypes.All
            }
        });

        if (files.Count > 0)
        {
            string? path = files[0].TryGetLocalPath();
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                _templateEditorBox.Text = await File.ReadAllTextAsync(path);
                RunActiveTemplate();
            }
        }
    }

    private void OpenFileIntoNewTab(string filePath)
    {
        var newDoc = BinaryDocument.OpenFile(filePath);
        // Replace initial untouched blank tab if it's still empty/unmodified
        if (_openDocuments.Count == 1 && _openDocuments[0].FilePath is null && !_openDocuments[0].IsModified)
        {
            var old = _openDocuments[0];
            _openDocuments[0] = newDoc;
            old.Dispose();
            SwitchToDocumentTab(0);
            return;
        }

        _openDocuments.Add(newDoc);
        SwitchToDocumentTab(_openDocuments.Count - 1);
    }

    private void AddNewBlankTab()
    {
        var blankDoc = new BinaryDocument(new byte[256], $"Untitled_{_openDocuments.Count + 1}.bin");
        _openDocuments.Add(blankDoc);
        SwitchToDocumentTab(_openDocuments.Count - 1);
    }

    private void ExecuteGotoOffset()
    {
        string raw = (_gotoOffsetBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(raw)) return;

        long target;
        if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!long.TryParse(raw[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out target))
                return;
        }
        else if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out target))
        {
            if (!long.TryParse(raw, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out target))
                return;
        }

        _hexEditor.JumpToOffset(target);
    }

    private void ExecuteFindNext()
    {
        string query = (_searchBox.Text ?? "").Trim();
        if (string.IsNullOrEmpty(query)) return;

        byte[] pattern;
        if (_searchModeCombo.SelectedIndex == 1)
        {
            var bytes = new List<byte>();
            string cleaned = query.Replace("0x", " ").Replace(",", " ").Replace("-", " ");
            foreach (string part in cleaned.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (byte.TryParse(part, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte b))
                    bytes.Add(b);
            }
            pattern = bytes.ToArray();
        }
        else
        {
            pattern = Encoding.UTF8.GetBytes(query);
        }

        if (pattern.Length == 0) return;

        long start = _hexEditor.CursorOffset + 1;
        long found = _document.FindPattern(pattern, start);
        if (found < 0 && start > 0)
            found = _document.FindPattern(pattern, 0);

        if (found >= 0)
        {
            _hexEditor.SelectRange(found, pattern.Length);
        }
    }

    private Border CreateTitledPane(string title, Control content)
    {
        var outer = new Border
        {
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(5)
        };

        var grid = new Grid { RowDefinitions = new RowDefinitions("26,*") };

        var titleText = new TextBlock
        {
            Text = title,
            FontSize = 11,
            FontWeight = FontWeight.Bold,
            VerticalAlignment = VerticalAlignment.Center
        };

        var headerBorder = new Border
        {
            CornerRadius = new CornerRadius(5, 5, 0, 0),
            Padding = new Thickness(8, 4),
            Child = titleText
        };

        var bodyBorder = new Border
        {
            Padding = new Thickness(6),
            Child = content
        };

        Grid.SetRow(headerBorder, 0);
        Grid.SetRow(bodyBorder, 1);
        grid.Children.Add(headerBorder);
        grid.Children.Add(bodyBorder);
        outer.Child = grid;

        _titledPanes.Add((outer, headerBorder, titleText));
        return outer;
    }

    private GridSplitter CreateSplitter(GridResizeDirection dir)
    {
        var s = new GridSplitter { ResizeDirection = dir };
        _splitters.Add(s);
        return s;
    }

    private TextBlock CreateToolbarLabel(string text, Thickness margin, bool bold = false)
    {
        var tb = new TextBlock
        {
            Text = text,
            FontSize = 11.5,
            FontWeight = bold ? FontWeight.SemiBold : FontWeight.Normal,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = margin
        };
        _toolbarLabels.Add(tb);
        return tb;
    }

    private Button CreateActionButton(
        string text,
        string accentRole,
        EventHandler<Avalonia.Interactivity.RoutedEventArgs> onClick)
    {
        var btn = new Button
        {
            Content = text,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 3),
            Margin = new Thickness(2, 0),
            FontSize = 11.5,
            FontWeight = FontWeight.SemiBold
        };
        btn.Click += onClick;
        _themedButtons.Add((btn, accentRole));
        return btn;
    }

    private static TextBlock CreateStatusText(string text)
    {
        return new TextBlock
        {
            Text = text,
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 11.5,
            VerticalAlignment = VerticalAlignment.Center
        };
    }
}
