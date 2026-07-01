package auto

import (
	"errors"
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Valid test messages
const (
	validRFC5424 = `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`
	validRFC3164 = `<13>Dec  2 16:31:03 host app: Test`
)

// --- Zero-config ---

func TestNewMachine_ZeroConfig_RFC5424(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte(validRFC5424))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
	assert.Equal(t, uint8(165), *msg.(*rfc5424.SyslogMessage).Priority)
}

func TestNewMachine_ZeroConfig_RFC3164(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte(validRFC3164))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
	assert.Equal(t, "host", *msg.(*rfc3164.SyslogMessage).Hostname)
}

// --- Detection accuracy ---

func TestParse_RFC5424_Versions(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"v1", `<34>1 2025-01-03T14:07:15.003Z host app pid msgid - msg`},
		{"v12", `<34>12 2025-01-03T14:07:15.003Z host app pid msgid - msg`},
	}
	m := NewMachine()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := m.Parse([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, FormatRFC5424, DetectFormat(msg))
		})
	}
}

func TestParse_RFC3164_LeadingSpaces(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte("<13> Dec  2 16:31:03 host app: Test"))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
}

func TestParse_RFC3164_CiscoCounter(t *testing.T) {
	m := NewMachine(WithRFC3164Options(
		rfc3164.WithMessageCounter(),
	))
	msg, err := m.Parse([]byte("<189>237: Jan  8 19:46:03 host msg"))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
}

func TestParse_RFC3164_CiscoStar(t *testing.T) {
	m := NewMachine(WithRFC3164Options(
		rfc3164.WithMessageCounter(),
	))
	msg, err := m.Parse([]byte("<189>237: *Jan  8 19:46:03 host msg"))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
}

func TestParse_EdgePriorities(t *testing.T) {
	m := NewMachine()
	tests := []struct {
		name   string
		input  string
		format Format
	}{
		{"pri0 rfc5424", "<0>1 2025-01-03T14:07:15Z h a p m - msg", FormatRFC5424},
		{"pri191 rfc5424", "<191>1 2025-01-03T14:07:15Z h a p m - msg", FormatRFC5424},
		{"pri0 rfc3164", "<0>Jan  1 00:00:00 host app: msg", FormatRFC3164},
		{"pri191 rfc3164", "<191>Oct 11 22:14:15 host app: msg", FormatRFC3164},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := m.Parse([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.format, DetectFormat(msg))
		})
	}
}

// --- Fallback ---

func TestParse_Fallback_PeekSays5424_FallsBackTo3164(t *testing.T) {
	// Peek sees "1 " → RFC 5424. RFC 5424 parse fails (invalid timestamp).
	// Fallback to RFC 3164 with best-effort may extract partial data.
	// Both fail without best-effort → ParseError.
	m := NewMachine()
	msg, err := m.Parse([]byte("<34>1 not-valid-anything"))
	assert.Nil(t, msg)
	require.Error(t, err)
	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, []byte("<34>1 not-valid-anything"), pe.RawMessage)
}

func TestParse_Fallback_SecondarySucceeds(t *testing.T) {
	// Best-effort via format-specific options is filtered from strict machines
	// and only applied to BE machines. The three-tier strategy is:
	// 1. Strict primary (5424) fails
	// 2. Strict secondary (3164, truly strict) fails
	// 3. BE primary (5424) recovers partial
	m := NewMachine(WithRFC3164Options(rfc3164.WithBestEffort()))
	input := []byte("<34>1 not-a-valid-5424-timestamp")
	msg, err := m.Parse(input)
	require.NotNil(t, msg, "best-effort primary should recover partial result")
	assert.Error(t, err)
	// BE recovery uses the peek-chosen parser (5424), not the fallback.
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestParse_Fallback_BothFail_ReturnsParseError(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte("garbage"))
	assert.Nil(t, msg)
	require.Error(t, err)

	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, []byte("garbage"), pe.RawMessage)
	assert.NotNil(t, pe.Err)
}

func TestParse_WithoutFallback_NoRetry(t *testing.T) {
	m := NewMachine(WithoutFallback())
	// Peek says 5424 (digit + space), but message is invalid.
	msg, err := m.Parse([]byte("<34>1 garbage"))
	assert.Nil(t, msg)
	require.Error(t, err)

	var pe *ParseError
	require.True(t, errors.As(err, &pe))
}

func TestParse_WithoutFallback_ValidMessage(t *testing.T) {
	m := NewMachine(WithoutFallback())
	msg, err := m.Parse([]byte(validRFC5424))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestParse_WithoutFallback_PrioritylessRFC3164(t *testing.T) {
	m := NewMachine(
		WithoutFallback(),
		WithRFC3164Options(rfc3164.WithOptionalPriority()),
	)

	msg, err := m.Parse([]byte("Oct 11 22:14:15 mymachine su: message"))

	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
	sm, ok := msg.(*rfc3164.SyslogMessage)
	require.True(t, ok)
	assert.Nil(t, sm.Priority)
}

func TestParse_WithoutFallback_PrioritylessRFC3164RFC3339(t *testing.T) {
	m := NewMachine(
		WithoutFallback(),
		WithRFC3164Options(
			rfc3164.WithOptionalPriority(),
			rfc3164.WithRFC3339(),
		),
	)

	msg, err := m.Parse([]byte("2025-01-03T14:07:15Z host app: message"))

	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
	sm, ok := msg.(*rfc3164.SyslogMessage)
	require.True(t, ok)
	assert.Nil(t, sm.Priority)
}

func TestParse_WithoutFallback_PrioritylessRFC5424(t *testing.T) {
	m := NewMachine(
		WithoutFallback(),
		WithRFC5424Options(rfc5424.WithOptionalPriority()),
	)

	msg, err := m.Parse([]byte("1 2025-01-03T14:07:15Z host app - - - message"))

	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
	sm, ok := msg.(*rfc5424.SyslogMessage)
	require.True(t, ok)
	assert.Nil(t, sm.Priority)
}

// --- Best-effort ---

func TestParse_BestEffort_PartialResult_NoFallback(t *testing.T) {
	m := NewMachine(WithRFC5424Options(rfc5424.WithBestEffort()))
	// Truncated RFC 5424 — best-effort should return partial result.
	input := []byte("<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut=\"3\"")
	msg, err := m.Parse(input)
	// Best-effort returns partial message (non-nil) with error.
	require.NotNil(t, msg, "best-effort should return partial message")
	assert.Error(t, err)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
	// No fallback should have been attempted since msg is non-nil.
}

func TestParse_BestEffort_PromotionPreservesNonBEOptions(t *testing.T) {
	// When best-effort is promoted from format-specific options, non-best-effort
	// options (like WithCompliantMsg) must be preserved on the strict machines.
	m := NewMachine(
		WithRFC5424Options(rfc5424.WithBestEffort(), rfc5424.WithCompliantMsg()),
	)
	assert.True(t, m.HasBestEffort())
	// Valid 5424 with BOM in MSG — WithCompliantMsg must be active on strict machine.
	input := []byte("<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 - \xEF\xBB\xBFmsg")
	msg, err := m.Parse(input)
	require.NotNil(t, msg)
	assert.NoError(t, err)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestParse_BestEffort_ViaWithBestEffort_AfterPromotion(t *testing.T) {
	// WithBestEffort() is a no-op if best-effort was already promoted
	// from format-specific options during NewMachine construction.
	m := NewMachine(WithRFC5424Options(rfc5424.WithBestEffort()))
	assert.True(t, m.HasBestEffort())
	m.WithBestEffort() // should be a no-op
	assert.True(t, m.HasBestEffort())
}

func TestParse_BestEffort_ViaWithBestEffort(t *testing.T) {
	m := NewMachine()
	assert.False(t, m.HasBestEffort())
	m.WithBestEffort()
	assert.True(t, m.HasBestEffort())
	// Truncated RFC 5424 — best-effort returns partial result.
	input := []byte("<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut=\"3\"")
	msg, err := m.Parse(input)
	require.NotNil(t, msg, "best-effort should return partial message")
	assert.Error(t, err)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestParse_HasBestEffort(t *testing.T) {
	m := NewMachine()
	assert.False(t, m.HasBestEffort())
}

func TestParse_BestEffort_FallbackStillWorks(t *testing.T) {
	// With best-effort enabled via WithBestEffort(), strict parsing is tried
	// first. A valid message that peek correctly identifies should parse
	// via the strict primary — not the best-effort path.
	m := NewMachine()
	m.WithBestEffort()

	// Valid 5424 — strict primary succeeds, no fallback or best-effort needed.
	msg, err := m.Parse([]byte(validRFC5424))
	require.NotNil(t, msg)
	assert.NoError(t, err)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))

	// Valid 3164 — strict primary succeeds.
	msg2, err2 := m.Parse([]byte(validRFC3164))
	require.NotNil(t, msg2)
	assert.NoError(t, err2)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg2))
}

func TestParse_BestEffort_PartialRecoveryAfterBothStrictFail_RFC5424(t *testing.T) {
	// Both strict parsers fail, best-effort recovers partial data from primary.
	m := NewMachine()
	m.WithBestEffort()

	// Truncated 5424: peek says 5424, strict 5424 fails, strict 3164 fails,
	// best-effort 5424 recovers partial.
	input := []byte("<165>4 2018-10-11T22:14:15.003Z")
	msg, err := m.Parse(input)
	require.NotNil(t, msg, "best-effort should recover partial data")
	assert.Error(t, err)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestParse_BestEffort_PartialRecoveryAfterBothStrictFail_RFC3164(t *testing.T) {
	// Peek says 3164 (starts with letter), both strict fail,
	// best-effort 3164 recovers partial.
	m := NewMachine()
	m.WithBestEffort()

	// Truncated 3164: valid PRI + month start but truncated before full timestamp.
	input := []byte("<13>Jan")
	msg, err := m.Parse(input)
	require.NotNil(t, msg, "best-effort 3164 should recover partial data")
	assert.Error(t, err)
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
}

// --- Format-specific options ---

func TestParse_RFC3164Options_WithYear(t *testing.T) {
	m := NewMachine(WithRFC3164Options(
		rfc3164.WithYear(rfc3164.Year{YYYY: 2025}),
	))
	msg, err := m.Parse([]byte("<13>Dec  2 16:31:03 host app: Test"))
	require.NoError(t, err)
	require.NotNil(t, msg)
	sm := msg.(*rfc3164.SyslogMessage)
	require.NotNil(t, sm.Timestamp)
	assert.Equal(t, 2025, sm.Timestamp.Year())
}

func TestParse_RFC5424Options_WithCompliantMsg(t *testing.T) {
	m := NewMachine(WithRFC5424Options(rfc5424.WithCompliantMsg()))
	msg, err := m.Parse([]byte(validRFC5424))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestParse_OptionsDoNotLeak(t *testing.T) {
	// RFC 3164 options should not affect RFC 5424 parsing.
	m := NewMachine(WithRFC3164Options(
		rfc3164.WithYear(rfc3164.Year{YYYY: 2025}),
	))
	msg, err := m.Parse([]byte(validRFC5424))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

// --- Empty / edge inputs ---

func TestParse_EmptyInput(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte(""))
	assert.Nil(t, msg)
	require.Error(t, err)

	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	assert.Empty(t, pe.RawMessage)
}

func TestParse_NilInput(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse(nil)
	assert.Nil(t, msg)
	require.Error(t, err)

	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	assert.Nil(t, pe.RawMessage)
}

func TestParse_PRIOnly(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte("<34>"))
	assert.Nil(t, msg)
	require.Error(t, err)

	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	assert.Equal(t, []byte("<34>"), pe.RawMessage)
}

// --- Interface compliance ---

func TestMachine_ImplementsSyslogMachine(t *testing.T) {
	var _ syslog.Machine = NewMachine()
}
