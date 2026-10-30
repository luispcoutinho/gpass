package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

func stdinTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// promptLine reads a visible line from stdin, prompting on stderr.
func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label+": ")
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// optName is like splitName but the leading <name> is optional.
func optName(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", fs.Parse(args)
	}
	return args[0], fs.Parse(args[1:])
}

// pick lists entries accepted by keep and asks the user to choose one.
func pick(v *Vault, keep func(Entry) bool, usage string) (string, error) {
	if !stdinTTY() {
		return "", errors.New(usage)
	}
	var names []string
	for _, n := range v.Names() {
		if keep == nil || keep(v.Entries[n]) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", errors.New("no matching entries")
	}
	items := make([]pickItem, len(names))
	for i, n := range names {
		items[i] = pickItem{n, v.Entries[n].Username}
	}
	switch name, err := selectEntry(items); {
	case err == nil:
		return name, nil
	case !errors.Is(err, errNoUI):
		return "", err
	}
	// No usable terminal UI (for example stderr is redirected): numbered list.
	tw := tabwriter.NewWriter(os.Stderr, 0, 0, 3, ' ', 0)
	for i, it := range items {
		user := it.user
		if user == "" {
			user = "-"
		}
		fmt.Fprintf(tw, "%d)\t%s\t%s\n", i+1, it.name, user)
	}
	tw.Flush()
	in, err := promptLine("Select entry (number or name)")
	if err != nil {
		return "", err
	}
	return resolveChoice(names, in)
}

// resolveChoice maps user input to an entry: exact name, then number, then a
// unique case-insensitive substring.
func resolveChoice(names []string, in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("no selection")
	}
	for _, n := range names {
		if n == in {
			return n, nil
		}
	}
	if i, err := strconv.Atoi(in); err == nil {
		if i < 1 || i > len(names) {
			return "", fmt.Errorf("choice %d is out of range", i)
		}
		return names[i-1], nil
	}
	var hits []string
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), strings.ToLower(in)) {
			hits = append(hits, n)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("no entry matches %q", in)
	}
	return "", fmt.Errorf("%q matches several entries: %s", in, strings.Join(hits, ", "))
}
