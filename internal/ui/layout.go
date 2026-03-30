// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// Pane identifies which half of the split screen currently has keyboard focus.
type Pane int

const (
	// PaneTrace is the left pane showing the execution trace tree.
	PaneTrace Pane = iota
	// PaneState is the right pane showing the state key-value table.
	PaneState
)

// String returns a display label for the pane.
func (p Pane) String() string {
	if p == PaneTrace {
		return "Trace"
	}
	return "State"
}

type SplitLayout struct {
	Width  int
	Height int
	Focus  Pane

	LeftTitle  string
	RightTitle string
	SplitRatio float64

	resizeCh chan struct{}
}

// NewSplitLayout creates a SplitLayout sized to the current terminal.
func NewSplitLayout() *SplitLayout {
	w, h := TermSize()
	return &SplitLayout{
		Width:      w,
		Height:     h,
		Focus:      PaneTrace,
		LeftTitle:  "Trace",
		RightTitle: "State",
		SplitRatio: 0.5,
		resizeCh:   make(chan struct{}, 1),
	}
}

// ToggleFocus switches keyboard focus to the other pane and returns the new
// active pane. This is the action bound to the Tab key.
func (l *SplitLayout) ToggleFocus() Pane {
	if l.Focus == PaneTrace {
		l.Focus = PaneState
	} else {
		l.Focus = PaneTrace
	}
	return l.Focus
}

// SetFocus moves focus to the specified pane.
func (l *SplitLayout) SetFocus(p Pane) {
	l.Focus = p
}

// LeftWidth returns the number of columns allocated to the left (trace) pane,
// excluding the centre divider character.
func (l *SplitLayout) LeftWidth() int {
	ratio := l.SplitRatio
	if ratio <= 0 || ratio >= 1 {
		ratio = 0.5
	}
	w := int(float64(l.Width) * ratio)
	if w < 10 {
		w = 10
	}
	return w
}

// RightWidth returns the number of columns allocated to the right (state) pane.
func (l *SplitLayout) RightWidth() int {
	return l.Width - l.LeftWidth() - 1 // –1 for the divider
}

func (l *SplitLayout) ListenResize() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)

	go func() {
		for range sig {
			w, h := TermSize()
			l.Width = w
			l.Height = h
			// Non-blocking send — skip if the consumer hasn't processed the
			// previous event yet.
			select {
			case l.resizeCh <- struct{}{}:
			default:
			}
		}
	}()

	return l.resizeCh
}

func (l *SplitLayout) Render(leftLines, rightLines []string) {
	lw := l.LeftWidth()
	rw := l.RightWidth()
	contentRows := l.Height - 3
	if contentRows < 1 {
		contentRows = 1
	}

	sb := &strings.Builder{}

	// ── Top border ────────────────────────────────────────────────────────────
	sb.WriteString(l.borderRow(lw, rw))
	sb.WriteByte('\n')

	// ── Content rows ─────────────────────────────────────────────────────────
	for row := 0; row < contentRows; row++ {
		leftCell := cellAt(leftLines, row, lw)
		rightCell := cellAt(rightLines, row, rw)

		sb.WriteString(l.panePrefix(PaneTrace))
		sb.WriteString(leftCell)
		sb.WriteString(l.divider())
		sb.WriteString(l.panePrefix(PaneState))
		sb.WriteString(rightCell)
		sb.WriteByte('\n')
	}

	// ── Bottom border ────────────────────────────────────────────────────────
	bottom := "+" + strings.Repeat("-", lw) + "+" + strings.Repeat("-", rw) + "+"
	sb.WriteString(bottom)
	sb.WriteByte('\n')

	// ── Status bar ───────────────────────────────────────────────────────────
	status := fmt.Sprintf(" [focus: %s]  %s", l.Focus, KeyHelp())
	if len(status) > l.Width {
		status = status[:l.Width]
	}
	sb.WriteString(status)

	fmt.Print(sb.String())
}

// borderRow builds the top border string with centred pane titles.
//
//	+──── Trace ─────+──── State ─────+
func (l *SplitLayout) borderRow(lw, rw int) string {
	leftLabel := l.fmtTitle(l.LeftTitle, l.Focus == PaneTrace, lw)
	rightLabel := l.fmtTitle(l.RightTitle, l.Focus == PaneState, rw)
	return "+" + leftLabel + "+" + rightLabel + "+"
}

func (l *SplitLayout) fmtTitle(title string, focused bool, width int) string {
	marker := ""
	if focused {
		marker = "*" // simple ASCII focus marker visible in all terminals
	}
	label := fmt.Sprintf(" %s%s ", marker, title)
	pad := width - len(label)
	if pad < 0 {
		return label[:width]
	}
	left := pad / 2
	right := pad - left
	return strings.Repeat("─", left) + label + strings.Repeat("─", right)
}

func (l *SplitLayout) divider() string {
	return "│"
}

// panePrefix is a hook for future per-pane colouring (currently a no-op).
func (l *SplitLayout) panePrefix(_ Pane) string {
	return ""
}

func cellAt(lines []string, row, width int) string {
	text := ""
	if row < len(lines) {
		text = lines[row]
	}
	// Strip any embedded newlines that would break the layout.
	text = strings.ReplaceAll(text, "\n", " ")

	if len(text) > width {
		return text[:width]
	}
	return text + strings.Repeat(" ", width-len(text))
}
