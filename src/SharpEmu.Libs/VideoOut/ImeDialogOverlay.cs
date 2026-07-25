// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Diagnostics;

namespace SharpEmu.Libs.VideoOut;

/// <summary>
/// In-window text-entry panel for libSceImeDialog. Rasterized on the CPU into a
/// small BGRA buffer each frame (same technique as <see cref="PerfOverlay"/>,
/// an embedded 5x7 bitmap font, no GPU pipeline or shader assets) and blitted
/// onto the swapchain image by the presenter while a dialog is open.
/// </summary>
/// <remarks>
/// The bitmap font only covers ASCII 32..90 (space through 'Z'), so rendering
/// upper-cases everything for display, matching <see cref="PerfOverlay"/>'s
/// existing behavior. The text actually returned to the guest (<see cref="CurrentText"/>)
/// preserves the real typed case.
/// </remarks>
public static class ImeDialogOverlay
{
    public const int PanelWidth = 560;
    public const int PanelHeight = 140;

    private const int GlyphColumns = 5;
    private const int GlyphRows = 7;
    private const int Scale = 3;
    private const int CellWidth = (GlyphColumns + 1) * Scale;
    private const int LineHeight = (GlyphRows + 2) * Scale;
    private const int MaxDisplayLength = 64;

    private static readonly object _gate = new();
    private static readonly System.Text.StringBuilder _text = new();
    private static volatile bool _isOpen;
    private static string _title = string.Empty;
    private static int _maxLength = 1;
    private static long _lastCaretToggleTicks;
    private static bool _caretVisible = true;

    public static bool IsOpen => _isOpen;

    /// <summary>Opens the panel with the guest-supplied title and initial text.</summary>
    public static void Open(string title, string initialText, int maxLength)
    {
        lock (_gate)
        {
            _title = title ?? string.Empty;
            _text.Clear();
            _text.Append(initialText ?? string.Empty);
            _maxLength = Math.Max(1, maxLength);
            _isOpen = true;
            _caretVisible = true;
            _lastCaretToggleTicks = Stopwatch.GetTimestamp();
        }
    }

    public static void Close()
    {
        lock (_gate)
        {
            _isOpen = false;
        }
    }

    /// <summary>The real, case-preserved text currently entered.</summary>
    public static string CurrentText
    {
        get
        {
            lock (_gate)
            {
                return _text.ToString();
            }
        }
    }

    public static void AppendChar(char c)
    {
        lock (_gate)
        {
            if (!_isOpen || _text.Length >= _maxLength)
            {
                return;
            }

            _text.Append(c);
        }
    }

    public static void Backspace()
    {
        lock (_gate)
        {
            if (!_isOpen || _text.Length == 0)
            {
                return;
            }

            _text.Length--;
        }
    }

    /// <summary>
    /// Rasterizes the panel into a BGRA byte span of PanelWidth x PanelHeight.
    /// Runs on the render thread.
    /// </summary>
    public static void Fill(Span<byte> bgra)
    {
        string title;
        string text;
        lock (_gate)
        {
            title = _title;
            text = _text.ToString();
        }

        var now = Stopwatch.GetTimestamp();
        if ((now - _lastCaretToggleTicks) / (double)Stopwatch.Frequency >= 0.5)
        {
            _caretVisible = !_caretVisible;
            _lastCaretToggleTicks = now;
        }

        // Background: opaque dark slate, matching PerfOverlay's palette.
        for (var i = 0; i < bgra.Length; i += 4)
        {
            bgra[i] = 0x18;
            bgra[i + 1] = 0x14;
            bgra[i + 2] = 0x10;
            bgra[i + 3] = 0xFF;
        }

        DrawBorder(bgra, 0xB0, 0xB0, 0xB0);

        var y = 10;
        DrawString(bgra, 12, y, title.Length > 0 ? title : "ENTER TEXT", 0xFF, 0xD0, 0x80);
        y += LineHeight + 6;

        DrawHorizontalLine(bgra, 12, y, PanelWidth - 24, 0x60, 0x60, 0x60);
        y += 10;

        var display = text.Length > MaxDisplayLength ? text[^MaxDisplayLength..] : text;
        DrawString(bgra, 12, y, display, 0xFF, 0xFF, 0xFF);
        if (_caretVisible)
        {
            var caretX = 12 + display.Length * CellWidth;
            DrawString(bgra, caretX, y, "_", 0x60, 0xFF, 0x60);
        }

        y += LineHeight + 10;
        DrawString(bgra, 12, y, "ENTER=CONFIRM  ESC=CANCEL  BACKSPACE=DELETE", 0xB0, 0xB0, 0xB0);
    }

    private static void DrawBorder(Span<byte> bgra, byte r, byte g, byte b)
    {
        DrawHorizontalLine(bgra, 0, 0, PanelWidth, r, g, b);
        DrawHorizontalLine(bgra, 0, PanelHeight - 1, PanelWidth, r, g, b);
        for (var y = 0; y < PanelHeight; y++)
        {
            SetPixel(bgra, 0, y, r, g, b);
            SetPixel(bgra, PanelWidth - 1, y, r, g, b);
        }
    }

    private static void DrawHorizontalLine(Span<byte> bgra, int x, int y, int width, byte r, byte g, byte b)
    {
        if (y < 0 || y >= PanelHeight)
        {
            return;
        }

        for (var px = 0; px < width; px++)
        {
            SetPixel(bgra, x + px, y, r, g, b);
        }
    }

    private static void DrawString(Span<byte> bgra, int x, int y, string text, byte r, byte g, byte b)
    {
        var penX = x;
        foreach (var rawChar in text)
        {
            var c = char.ToUpperInvariant(rawChar);
            if (c < ' ' || c > 'Z')
            {
                c = '?';
            }

            var glyph = Font.Slice((c - ' ') * GlyphColumns, GlyphColumns);
            for (var column = 0; column < GlyphColumns; column++)
            {
                var bits = glyph[column];
                for (var row = 0; row < GlyphRows; row++)
                {
                    if ((bits & (1 << row)) == 0)
                    {
                        continue;
                    }

                    for (var sy = 0; sy < Scale; sy++)
                    {
                        for (var sx = 0; sx < Scale; sx++)
                        {
                            SetPixel(bgra, penX + column * Scale + sx, y + row * Scale + sy, r, g, b);
                        }
                    }
                }
            }

            penX += CellWidth;
            if (penX + CellWidth > PanelWidth)
            {
                break;
            }
        }
    }

    private static void SetPixel(Span<byte> bgra, int x, int y, byte r, byte g, byte b)
    {
        if ((uint)x >= PanelWidth || (uint)y >= PanelHeight)
        {
            return;
        }

        var offset = (y * PanelWidth + x) * 4;
        bgra[offset] = b;
        bgra[offset + 1] = g;
        bgra[offset + 2] = r;
        bgra[offset + 3] = 0xFF;
    }

    // Classic 5x7 column-encoded font (bit 0 = top row), ASCII 32..90.
    // Duplicated from PerfOverlay rather than shared, since PerfOverlay's copy
    // is private and this keeps the two overlays independently maintainable.
    private static ReadOnlySpan<byte> Font =>
    [
        0x00, 0x00, 0x00, 0x00, 0x00, // ' '
        0x00, 0x00, 0x5F, 0x00, 0x00, // '!'
        0x00, 0x07, 0x00, 0x07, 0x00, // '"'
        0x14, 0x7F, 0x14, 0x7F, 0x14, // '#'
        0x24, 0x2A, 0x7F, 0x2A, 0x12, // '$'
        0x23, 0x13, 0x08, 0x64, 0x62, // '%'
        0x36, 0x49, 0x55, 0x22, 0x50, // '&'
        0x00, 0x05, 0x03, 0x00, 0x00, // '''
        0x00, 0x1C, 0x22, 0x41, 0x00, // '('
        0x00, 0x41, 0x22, 0x1C, 0x00, // ')'
        0x08, 0x2A, 0x1C, 0x2A, 0x08, // '*'
        0x08, 0x08, 0x3E, 0x08, 0x08, // '+'
        0x00, 0x50, 0x30, 0x00, 0x00, // ','
        0x08, 0x08, 0x08, 0x08, 0x08, // '-'
        0x00, 0x60, 0x60, 0x00, 0x00, // '.'
        0x20, 0x10, 0x08, 0x04, 0x02, // '/'
        0x3E, 0x51, 0x49, 0x45, 0x3E, // '0'
        0x00, 0x42, 0x7F, 0x40, 0x00, // '1'
        0x42, 0x61, 0x51, 0x49, 0x46, // '2'
        0x21, 0x41, 0x45, 0x4B, 0x31, // '3'
        0x18, 0x14, 0x12, 0x7F, 0x10, // '4'
        0x27, 0x45, 0x45, 0x45, 0x39, // '5'
        0x3C, 0x4A, 0x49, 0x49, 0x30, // '6'
        0x01, 0x71, 0x09, 0x05, 0x03, // '7'
        0x36, 0x49, 0x49, 0x49, 0x36, // '8'
        0x06, 0x49, 0x49, 0x29, 0x1E, // '9'
        0x00, 0x36, 0x36, 0x00, 0x00, // ':'
        0x00, 0x56, 0x36, 0x00, 0x00, // ';'
        0x00, 0x08, 0x14, 0x22, 0x41, // '<'
        0x14, 0x14, 0x14, 0x14, 0x14, // '='
        0x41, 0x22, 0x14, 0x08, 0x00, // '>'
        0x02, 0x01, 0x51, 0x09, 0x06, // '?'
        0x32, 0x49, 0x79, 0x41, 0x3E, // '@'
        0x7E, 0x11, 0x11, 0x11, 0x7E, // 'A'
        0x7F, 0x49, 0x49, 0x49, 0x36, // 'B'
        0x3E, 0x41, 0x41, 0x41, 0x22, // 'C'
        0x7F, 0x41, 0x41, 0x22, 0x1C, // 'D'
        0x7F, 0x49, 0x49, 0x49, 0x41, // 'E'
        0x7F, 0x09, 0x09, 0x09, 0x01, // 'F'
        0x3E, 0x41, 0x49, 0x49, 0x7A, // 'G'
        0x7F, 0x08, 0x08, 0x08, 0x7F, // 'H'
        0x00, 0x41, 0x7F, 0x41, 0x00, // 'I'
        0x20, 0x40, 0x41, 0x3F, 0x01, // 'J'
        0x7F, 0x08, 0x14, 0x22, 0x41, // 'K'
        0x7F, 0x40, 0x40, 0x40, 0x40, // 'L'
        0x7F, 0x02, 0x0C, 0x02, 0x7F, // 'M'
        0x7F, 0x04, 0x08, 0x10, 0x7F, // 'N'
        0x3E, 0x41, 0x41, 0x41, 0x3E, // 'O'
        0x7F, 0x09, 0x09, 0x09, 0x06, // 'P'
        0x3E, 0x41, 0x51, 0x21, 0x5E, // 'Q'
        0x7F, 0x09, 0x19, 0x29, 0x46, // 'R'
        0x46, 0x49, 0x49, 0x49, 0x31, // 'S'
        0x01, 0x01, 0x7F, 0x01, 0x01, // 'T'
        0x3F, 0x40, 0x40, 0x40, 0x3F, // 'U'
        0x1F, 0x20, 0x40, 0x20, 0x1F, // 'V'
        0x3F, 0x40, 0x38, 0x40, 0x3F, // 'W'
        0x63, 0x14, 0x08, 0x14, 0x63, // 'X'
        0x07, 0x08, 0x70, 0x08, 0x07, // 'Y'
        0x61, 0x51, 0x49, 0x45, 0x43, // 'Z'
    ];
}
