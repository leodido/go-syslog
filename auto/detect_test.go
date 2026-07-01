package auto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetect_RFC5424_Standard(t *testing.T) {
	// <PRI>VERSION SP ... → RFC 5424
	tests := []struct {
		name  string
		input string
	}{
		{"version 1", "<34>1 2025-01-03T14:07:15.003Z host app - - - msg"},
		{"version 12", "<165>12 2025-01-03T14:07:15Z host app - - - msg"},
		{"version 999", "<0>999 2025-01-03T14:07:15Z host app - - - msg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, FormatRFC5424, detect([]byte(tt.input)))
		})
	}
}

func TestDetect_RFC3164_MonthStart(t *testing.T) {
	// Letter after PRI → RFC 3164 (month abbreviation)
	tests := []struct {
		name  string
		input string
	}{
		{"uppercase", "<34>Oct 11 22:14:15 mymachine su: msg"},
		{"lowercase", "<34>oct 11 22:14:15 mymachine su: msg"},
		{"Jan", "<13>Jan  1 00:00:00 host msg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, FormatRFC3164, detect([]byte(tt.input)))
		})
	}
}

func TestDetect_RFC3164_LeadingSpace(t *testing.T) {
	// Space after PRI → RFC 3164
	assert.Equal(t, FormatRFC3164, detect([]byte("<34> Oct 11 22:14:15 host msg")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<34>  Jan  1 00:00:00 host msg")))
}

func TestDetect_RFC3164_CiscoStar(t *testing.T) {
	// '*' after PRI → RFC 3164 (Cisco NTP unsync marker)
	assert.Equal(t, FormatRFC3164, detect([]byte("<189>*Jan  8 19:46:03.295: msg")))
}

func TestDetect_RFC3164_ZeroAfterPRI(t *testing.T) {
	// '0' after PRI → RFC 3164 (version cannot start with 0)
	assert.Equal(t, FormatRFC3164, detect([]byte("<34>0 some garbage")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<34>0123: counter")))
}

func TestDetect_RFC3164_CiscoCounter(t *testing.T) {
	// Digit(s) followed by ':' → RFC 3164 (Cisco message counter)
	tests := []struct {
		name  string
		input string
	}{
		{"single digit", "<189>1: Jan  8 19:46:03 host msg"},
		{"multi digit", "<189>237: Jan  8 19:46:03.295 host msg"},
		{"three digits", "<189>999: Jan  8 19:46:03 host msg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, FormatRFC3164, detect([]byte(tt.input)))
		})
	}
}

func TestDetect_RFC3164_FourPlusDigits(t *testing.T) {
	// 4+ digits after PRI → RFC 3164 (version max 3 digits)
	assert.Equal(t, FormatRFC3164, detect([]byte("<189>1234: Jan  8 msg")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<189>12345 something")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<189>99999: msg")))
}

func TestDetect_RFC5424_DigitThenSpace(t *testing.T) {
	// 1-3 digits followed by SP → RFC 5424 (VERSION SP pattern).
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>1 rest")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>22 rest")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>333 rest")))

	// Edge case: a hypothetical Cisco message with single-digit counter
	// followed by space (e.g., "<189>1 Jan  8 ...") is classified as RFC 5424.
	// This is correct: RFC 3164 Cisco counters use "digits:" (colon, not space).
	// A digit followed by space is the RFC 5424 VERSION SP pattern.
	assert.Equal(t, FormatRFC5424, detect([]byte("<189>1 Jan  8 19:46:03 host msg")))
}

func TestDetect_RFC5424_DigitThenOther(t *testing.T) {
	// 1-3 digits followed by non-SP non-':' → default RFC 5424
	// This covers the RFC 3164 + WithRFC3339 case: <34>2025-01-03T...
	// Peek sees '2', then '0', '2', '5' → 4 digits → RFC 3164.
	// But for 1-3 digits followed by '-':
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>2-rest")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>1T2025")))
}

func TestDetect_RFC3164_RFC3339Timestamp(t *testing.T) {
	// <34>2025-01-03T... → starts with '2', scans '0','2','5' = 4 digits → RFC 3164
	assert.Equal(t, FormatRFC3164, detect([]byte("<34>2025-01-03T14:07:15Z host msg")))
}

func TestDetect_NoPRI(t *testing.T) {
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for _, month := range months {
		t.Run(month, func(t *testing.T) {
			input := fmt.Sprintf("%s  1 00:00:00 host app: msg", month)
			assert.Equal(t, FormatRFC3164, detect([]byte(input)))
		})
	}

	assert.Equal(t, FormatRFC3164, detect([]byte("2025-01-03T14:07:15Z host app: msg")))
	assert.Equal(t, FormatRFC5424, detect([]byte("1 2025-01-03T14:07:15Z host app - - - msg")))
	assert.Equal(t, FormatRFC5424, detect([]byte("1 2025-01-03T14:07:15Z host app - - - value > threshold")))
	assert.Equal(t, FormatRFC5424, detect([]byte("no pri here")))
	assert.Equal(t, FormatRFC5424, detect([]byte("")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34")))
}

func TestDetect_EmptyAfterPRI(t *testing.T) {
	// Nothing after '>' → default RFC 5424
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>")))
}

func TestDetect_OtherByteAfterPRI(t *testing.T) {
	// Non-letter, non-digit, non-space, non-'*' → default RFC 5424
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>!garbage")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>#stuff")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>\x01binary")))
}

func TestDetect_MalformedPRI(t *testing.T) {
	// detect() scans for the first '>' without validating PRI structure.
	// Both RFC parsers reject malformed PRI at col 0 regardless of the
	// detection result, so the choice here is inconsequential — these
	// tests document the current behavior.

	// Empty PRI value: <> — '>' at pos 1, classifies based on next byte.
	assert.Equal(t, FormatRFC5424, detect([]byte("<>1 rest")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<>Oct 11 msg")))

	// Non-numeric PRI: <abc> — '>' at pos 4, classifies based on next byte.
	assert.Equal(t, FormatRFC5424, detect([]byte("<abc>1 rest")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<abc>Oct 11 msg")))

	// Double '>': <34>> — first '>' is PRI closer, second '>' is post-PRI
	// byte which is not letter/digit/space/'*' → default RFC 5424.
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>>1 rest")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>>Oct 11 msg")))
}

func TestDetect_EdgePriorities(t *testing.T) {
	// Various priority values — detection depends on post-PRI bytes, not PRI value
	assert.Equal(t, FormatRFC5424, detect([]byte("<0>1 msg")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<191>1 msg")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<0>Jan  1 00:00:00 host msg")))
	assert.Equal(t, FormatRFC3164, detect([]byte("<191>Oct 11 22:14:15 host msg")))
}

func TestDetect_TruncatedDigitRun(t *testing.T) {
	// Digits after PRI but input ends before SP or ':' → default RFC 5424
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>1")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>12")))
	assert.Equal(t, FormatRFC5424, detect([]byte("<34>123")))
}

func TestDetect_AllMonths(t *testing.T) {
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for _, m := range months {
		t.Run(m, func(t *testing.T) {
			input := fmt.Sprintf("<34>%s  1 00:00:00 host msg", m)
			assert.Equal(t, FormatRFC3164, detect([]byte(input)))
		})
	}
}
