// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// writeCompletion writes a shell completion script for the given shell
// ("bash", "zsh", or "fish"), derived from the registered flags so it stays in
// sync automatically. It returns an error for an unknown shell.
func writeCompletion(w io.Writer, shell string) error {
	type fl struct{ name, usage string }
	var flags []fl
	flag.VisitAll(func(f *flag.Flag) {
		flags = append(flags, fl{f.Name, firstLine(f.Usage)})
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].name < flags[j].name })

	switch shell {
	case "bash":
		var names []string
		for _, f := range flags {
			names = append(names, "--"+f.name)
		}
		fmt.Fprintf(w, `# triton bash completion. Source it or install to a completions dir.
_triton() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local flags="%s"
    COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
}
complete -F _triton triton
`, strings.Join(names, " "))
	case "zsh":
		fmt.Fprintln(w, "#compdef triton")
		fmt.Fprintln(w, "_triton() {")
		fmt.Fprintln(w, "  _arguments \\")
		for i, f := range flags {
			end := " \\"
			if i == len(flags)-1 {
				end = ""
			}
			fmt.Fprintf(w, "    '--%s[%s]'%s\n", f.name, zshEscape(f.usage), end)
		}
		fmt.Fprintln(w, "}")
		fmt.Fprintln(w, "_triton")
	case "fish":
		for _, f := range flags {
			fmt.Fprintf(w, "complete -c triton -l %s -d '%s'\n", f.name, fishEscape(f.usage))
		}
	default:
		return fmt.Errorf("unknown shell %q (use bash, zsh, or fish)", shell)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func zshEscape(s string) string {
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "[", "(")
	s = strings.ReplaceAll(s, "]", ")")
	s = strings.ReplaceAll(s, ":", " ")
	return s
}

func fishEscape(s string) string {
	return strings.ReplaceAll(s, "'", "")
}
