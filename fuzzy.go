package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

type pickItem struct{ name, user string }

var (
	errCancelled = errors.New("cancelled")
	errNoUI      = errors.New("no interactive terminal")
)

type keyKind int

const (
	keyRune keyKind = iota
	keyUp
	keyDown
	keyEnter
	keyCancel
	keyBackspace
	keyClear
	keyDelWord
)

type keyEvent struct {
	k keyKind
	r rune
}

// parseKeys turns one terminal read into key events. Unknown escape sequences are dropped.
func parseKeys(b []byte) []keyEvent {
	var evs []keyEvent
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == 0x1b:
			if i+1 >= len(b) {
				evs = append(evs, keyEvent{k: keyCancel}) // bare Esc
				i++
				continue
			}
			if b[i+1] == '[' || b[i+1] == 'O' {
				j := i + 2
				for j < len(b) && !(b[j] >= 0x40 && b[j] <= 0x7e) {
					j++
				}
				if j < len(b) {
					switch b[j] {
					case 'A':
						evs = append(evs, keyEvent{k: keyUp})
					case 'B':
						evs = append(evs, keyEvent{k: keyDown})
					}
				}
				i = j + 1
				continue
			}
			i += 2 // Alt+key: ignore
		case c == '\r' || c == '\n':
			evs = append(evs, keyEvent{k: keyEnter})
			i++
		case c == 3 || c == 4 || c == 7: // ctrl-c, ctrl-d, ctrl-g
			evs = append(evs, keyEvent{k: keyCancel})
			i++
		case c == 16: // ctrl-p
			evs = append(evs, keyEvent{k: keyUp})
			i++
		case c == 14: // ctrl-n
			evs = append(evs, keyEvent{k: keyDown})
			i++
		case c == 127 || c == 8:
			evs = append(evs, keyEvent{k: keyBackspace})
			i++
		case c == 21: // ctrl-u
			evs = append(evs, keyEvent{k: keyClear})
			i++
		case c == 23: // ctrl-w
			evs = append(evs, keyEvent{k: keyDelWord})
			i++
		case c < 0x20:
			i++
		default:
			r, size := utf8.DecodeRune(b[i:])
			if r != utf8.RuneError {
				evs = append(evs, keyEvent{k: keyRune, r: r})
			}
			i += size
		}
	}
	return evs
}

// termScore reports whether q matches text. An exact substring beats a looser
// subsequence match; lower scores rank first.
func termScore(text, q string) (int, bool) {
	if i := strings.Index(text, q); i >= 0 {
		return i, true
	}
	tr, qr := []rune(text), []rune(q)
	pos, firstIdx, gaps, last := 0, -1, 0, -1
	for i, c := range tr {
		if pos < len(qr) && c == qr[pos] {
			if firstIdx < 0 {
				firstIdx = i
			}
			if last >= 0 {
				gaps += i - last - 1
			}
			last = i
			pos++
		}
	}
	if pos < len(qr) {
		return 0, false
	}
	return 1000 + firstIdx + gaps, true
}

// filterItems returns the indexes of items matching every space-separated term
// of query, best matches first. An empty query keeps the original order.
func filterItems(items []pickItem, query string) []int {
	terms := strings.Fields(strings.ToLower(query))
	type hit struct{ idx, score int }
	var hits []hit
	for i, it := range items {
		text := strings.ToLower(it.name + " " + it.user)
		total, ok := 0, true
		for _, t := range terms {
			s, m := termScore(text, t)
			if !m {
				ok = false
				break
			}
			total += s
		}
		if ok {
			hits = append(hits, hit{i, total})
		}
	}
	sort.SliceStable(hits, func(a, b int) bool { return hits[a].score < hits[b].score })
	idx := make([]int, len(hits))
	for i, h := range hits {
		idx[i] = h.idx
	}
	return idx
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// selectEntry runs an fzf-style picker on the terminal: type to filter, up/down
// to move, Enter to select, Esc or ctrl-c to cancel. The UI is drawn on stderr.
func selectEntry(items []pickItem) (string, error) {
	in, out := int(os.Stdin.Fd()), int(os.Stderr.Fd())
	if w, _, err := term.GetSize(out); err != nil || w < 20 {
		return "", errNoUI
	}
	old, err := term.MakeRaw(in)
	if err != nil {
		return "", errNoUI
	}
	defer term.Restore(in, old)

	nameW := 0
	for _, it := range items {
		if n := utf8.RuneCountInString(it.name); n > nameW {
			nameW = n
		}
	}

	var (
		query    []rune
		idx      = filterItems(items, "")
		sel, off int
		buf      = make([]byte, 64)
	)
	refresh := func() {
		idx = filterItems(items, string(query))
		if sel >= len(idx) {
			sel = len(idx) - 1
		}
		if sel < 0 {
			sel = 0
		}
	}
	draw := func() {
		w, h, err := term.GetSize(out)
		if err != nil {
			w, h = 80, 24
		}
		vis := h - 4
		if vis > 10 {
			vis = 10
		}
		if vis < 1 {
			vis = 1
		}
		if sel < off {
			off = sel
		}
		if sel >= off+vis {
			off = sel - vis + 1
		}
		var b bytes.Buffer
		prompt := "> " + string(query)
		b.WriteString("\r\x1b[J" + truncate(prompt, w-1))
		fmt.Fprintf(&b, "\r\n\x1b[2m  %d/%d\x1b[0m", len(idx), len(items))
		shown := 0
		for i := off; i < len(idx) && i < off+vis; i++ {
			it := items[idx[i]]
			line := fmt.Sprintf("%-*s  %s", nameW, it.name, it.user)
			line = truncate(strings.TrimRight(line, " "), w-3)
			if i == sel {
				b.WriteString("\r\n\x1b[7m> " + line + "\x1b[0m")
			} else {
				b.WriteString("\r\n  " + line)
			}
			shown++
		}
		fmt.Fprintf(&b, "\x1b[%dA\r", shown+1)
		if c := utf8.RuneCountInString(truncate(prompt, w-1)); c > 0 {
			fmt.Fprintf(&b, "\x1b[%dC", c)
		}
		os.Stderr.Write(b.Bytes())
	}
	clear := func() { os.Stderr.WriteString("\r\x1b[J") }

	for {
		draw()
		n, err := os.Stdin.Read(buf)
		if err != nil {
			clear()
			return "", err
		}
		for _, ev := range parseKeys(buf[:n]) {
			switch ev.k {
			case keyUp:
				if sel > 0 {
					sel--
				}
			case keyDown:
				if sel < len(idx)-1 {
					sel++
				}
			case keyRune:
				query = append(query, ev.r)
				sel, off = 0, 0
			case keyBackspace:
				if len(query) > 0 {
					query = query[:len(query)-1]
				}
				sel, off = 0, 0
			case keyClear:
				query, sel, off = nil, 0, 0
			case keyDelWord:
				s := strings.TrimRight(string(query), " ")
				if i := strings.LastIndex(s, " "); i >= 0 {
					s = s[:i+1]
				} else {
					s = ""
				}
				query, sel, off = []rune(s), 0, 0
			case keyEnter:
				if len(idx) > 0 {
					clear()
					return items[idx[sel]].name, nil
				}
			case keyCancel:
				clear()
				return "", errCancelled
			}
			refresh()
		}
	}
}
