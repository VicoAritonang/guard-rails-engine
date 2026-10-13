package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnv reads a .env file into the process environment.
//
// The one rule that matters: **a variable already present in the real
// environment always wins.** A .env file is a developer convenience for a
// laptop; the environment is what a container orchestrator, a CI runner, or a
// secrets manager injects. If the file overrode those, a stale committed
// default would silently outrank the credential your platform mounted, and the
// failure would look like "the wrong API key is somehow being used" with
// nothing to point at.
//
// A missing file is not an error. Production deployments are expected not to
// have one.
//
// Supported syntax, which is the intersection every dotenv implementation
// agrees on:
//
//	# a comment
//	KEY=value
//	export KEY=value            # the export prefix is tolerated and ignored
//	KEY="quoted value"          # \n and \t are unescaped inside double quotes
//	KEY='literal value'         # single quotes are literal
//	KEY=                        # explicit empty value
//
// Deliberately NOT supported: variable interpolation (${OTHER}), multi-line
// values, and command substitution. Each of those turns a config file into a
// small programming language, and the surprise they cause when a password
// happens to contain a "$" is not worth the convenience.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		key, value, ok, err := parseDotEnvLine(sc.Text())
		if err != nil {
			return fmt.Errorf("%s line %d: %w", path, line, err)
		}
		if !ok {
			continue
		}
		if _, present := os.LookupEnv(key); present {
			continue // the real environment wins; see the doc comment
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("%s line %d: set %s: %w", path, line, key, err)
		}
	}
	return sc.Err()
}

// parseDotEnvLine returns the key and value for one line. ok is false for
// blank lines and comments.
func parseDotEnvLine(raw string) (key, value string, ok bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false, nil
	}
	s = strings.TrimPrefix(s, "export ")

	name, rest, found := strings.Cut(s, "=")
	if !found {
		return "", "", false, fmt.Errorf("expected KEY=value, got %q", truncateLine(raw, 40))
	}
	key = strings.TrimSpace(name)
	if key == "" {
		return "", "", false, fmt.Errorf("empty key")
	}
	for _, r := range key {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' || r == '.') {
			return "", "", false, fmt.Errorf("invalid character %q in key %q", r, key)
		}
	}

	value = strings.TrimSpace(rest)
	switch {
	case len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"':
		value = value[1 : len(value)-1]
		value = strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\"`, `"`, `\\`, `\`).Replace(value)
	case len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'':
		value = value[1 : len(value)-1]
	default:
		// An unquoted value ends at an inline comment. Requiring whitespace
		// before the "#" keeps a "#" inside a generated key or password from
		// silently truncating it.
		if i := strings.Index(value, " #"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
	}
	return key, value, true, nil
}

func truncateLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
