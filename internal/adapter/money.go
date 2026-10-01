package adapter

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FormatMinor writes an amount in minor units as providers want it, with two decimals:
// 19900 → "199.00". Every currency the adapters here take (RUB, USD, EUR) has two.
// The amount must not be negative.
func FormatMinor(minor int64) string { return fmt.Sprintf("%d.%02d", minor/100, minor%100) }

// ParseMinor reads a provider's amount: "199.00", "199.5" or "199" → 19900, 19950, 19900.
// ok is false when the string is not a non-negative sum with at most two decimals.
func ParseMinor(s string) (minor int64, ok bool) {
	whole, frac, dot := strings.Cut(s, ".")
	if !digits(whole) || (dot && (len(frac) == 0 || len(frac) > 2 || !digits(frac))) {
		return 0, false
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || w >= math.MaxInt64/100 {
		return 0, false
	}
	frac += strings.Repeat("0", 2-len(frac))
	f, _ := strconv.ParseInt(frac, 10, 64)
	return w*100 + f, true
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Truncate cuts s to at most n characters (not bytes).
func Truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
