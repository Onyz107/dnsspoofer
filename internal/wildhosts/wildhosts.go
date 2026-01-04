package wildhosts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/Onyz107/dnsspoofer/internal/logger"
)

// Entry is one hosts entry: an IP and a single hostname pattern (may contain globs).
type Entry struct {
	IP      net.IP
	Pattern string // stored lowercased
}

// Hosts holds parsed entries.
type Hosts struct {
	Entries []Entry
}

// LoadFile loads hosts from a file path.
func LoadFile(ctx context.Context, filename string) (*Hosts, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(ctx, f)
}

// Parse parses hosts content from an io.Reader.
// Lines: IP <whitespace> PATTERN [# comment]
// Only one PATTERN allowed per line after IP (no aliases).
func Parse(ctx context.Context, r io.Reader) (*Hosts, error) {
	log := logger.LoggerFrom(ctx)

	h := &Hosts{}
	sc := bufio.NewScanner(r)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		// strip comments
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("%w: line %d", ErrMissingHostnamePattern, lineno)
		}
		if len(fields) > 2 {
			return nil, fmt.Errorf("%w: line %d", ErrAlias, lineno)
		}
		ipStr := fields[0]
		pattern := fields[1]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("%w: line %d", ErrInvalidIP, lineno)
		}
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			return nil, fmt.Errorf("%w: line %d", ErrEmptyHostname, lineno)
		}
		log.Debug("loaded entry", "ip", ip, "pattern", pattern)
		h.Entries = append(h.Entries, Entry{IP: ip, Pattern: pattern})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return h, nil
}

// Lookup returns all IPs that match the provided hostname (case-insensitive).
// The hostname supplied should be a plain hostname like "ads.doubleclick.net".
func (h *Hosts) Lookup(hostname string) []net.IP {
	if h == nil {
		return nil
	}
	hn := strings.ToLower(strings.TrimSpace(hostname))
	var out []net.IP
	for _, e := range h.Entries {
		ok, _ := path.Match(e.Pattern, hn)
		if ok {
			out = append(out, e.IP)
		}
	}
	return out
}

func (h *Hosts) Map() map[*regexp.Regexp][]net.IP {
	out := make(map[*regexp.Regexp][]net.IP)
	if h == nil {
		return out
	}
	for _, e := range h.Entries {
		pattern := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(e.Pattern), `\*`, ".*") + "$")
		out[pattern] = append(out[pattern], e.IP)
	}
	return out
}
