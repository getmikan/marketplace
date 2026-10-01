package adapter

import (
	"math"
	"testing"
)

func TestFormatMinor(t *testing.T) {
	for minor, want := range map[int64]string{0: "0.00", 1: "0.01", 50: "0.50", 19900: "199.00", 19950: "199.50", 100000005: "1000000.05"} {
		if got := FormatMinor(minor); got != want {
			t.Errorf("%d: %q, want %q", minor, got, want)
		}
	}
}

func TestParseMinor(t *testing.T) {
	for s, want := range map[string]int64{"199.00": 19900, "199.5": 19950, "199": 19900, "0.01": 1, "0": 0, "007.10": 710} {
		if got, ok := ParseMinor(s); !ok || got != want {
			t.Errorf("%q: %d %v, want %d", s, got, ok, want)
		}
	}
	for _, s := range []string{"", ".", "199.", ".5", "199.999", "-1", "+1", "1e2", " 1", "1,00", "1.0.0", "abc", "92233720368547758.07"} {
		if got, ok := ParseMinor(s); ok {
			t.Errorf("%q: accepted as %d", s, got)
		}
	}
	// Round trip.
	for _, minor := range []int64{1, 99, 100, 19900, math.MaxInt64 / 1000} {
		if got, ok := ParseMinor(FormatMinor(minor)); !ok || got != minor {
			t.Errorf("%d → %q → %d", minor, FormatMinor(minor), got)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("VPN · Месяц", 5); got != "VPN ·" {
		t.Fatalf("%q", got)
	}
	if got := Truncate("short", 10); got != "short" {
		t.Fatalf("%q", got)
	}
}
