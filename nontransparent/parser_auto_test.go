package nontransparent

import (
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/auto"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAuto_MixedStream(t *testing.T) {
	msg5424 := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`
	msg3164 := `<13>Dec  2 16:31:03 host app: Test message`

	stream := msg5424 + "\n" + msg3164 + "\n"

	var results []*syslog.Result
	p := NewParserAuto(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 2)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
	assert.Equal(t, auto.FormatRFC3164, auto.DetectFormat(results[1].Message))
}

func TestParseAuto_RFC5424Only(t *testing.T) {
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_RFC3164Only(t *testing.T) {
	msg := `<13>Dec  2 16:31:03 host app: Test message`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC3164, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_WithRFC3164MachineOptions(t *testing.T) {
	msg := `<13>Dec  2 16:31:03 host app: Test`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		auto.WithRFC3164MachineOptions(rfc3164.WithYear(rfc3164.Year{YYYY: 2025})),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	sm := results[0].Message.(*rfc3164.SyslogMessage)
	require.NotNil(t, sm.Timestamp)
	assert.Equal(t, 2025, sm.Timestamp.Year())
}

func TestParseAuto_WithRFC5424MachineOptions(t *testing.T) {
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] msg`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		auto.WithRFC5424MachineOptions(rfc5424.WithCompliantMsg()),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_WithoutFallback(t *testing.T) {
	// Message with valid PRI but invalid body — neither parser succeeds
	msg := `<13>!!!invalid`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		auto.WithoutParserFallback(),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.Nil(t, results[0].Message)
	assert.Error(t, results[0].Error)
}

func TestParseAuto_BestEffort(t *testing.T) {
	// Truncated RFC 5424 message — best-effort should return partial result
	msg := `<165>4 2018-10-11T22:14:15.003Z`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		syslog.WithBestEffort(),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Message, "best-effort should return partial message")
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_WithMachineOptions(t *testing.T) {
	// syslog.WithMachineOptions should forward to both inner parsers.
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"`
	stream := msg + "\n"

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		syslog.WithMachineOptions(rfc5424.WithBestEffort()),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Message)
	assert.Error(t, results[0].Error)
}

func TestParseAuto_WithMachineOptions_FormatSpecific(t *testing.T) {
	// Format-specific options via syslog.WithMachineOptions must not panic
	// when forwarded to the wrong inner machine type.
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] msg`
	stream := msg + "\n"

	var results []*syslog.Result
	assert.NotPanics(t, func() {
		p := NewParserAuto(
			syslog.WithListener(func(r *syslog.Result) {
				results = append(results, r)
			}),
			syslog.WithMachineOptions(rfc5424.WithCompliantMsg()),
		)
		p.Parse(strings.NewReader(stream))
	})

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Message)
	assert.NoError(t, results[0].Error)
}

func TestParseAuto_WithTrailer_NUL(t *testing.T) {
	msg5424 := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] msg`
	msg3164 := `<13>Dec  2 16:31:03 host app: Test`

	nul, _ := NUL.Value()
	sep := string(rune(nul))
	stream := msg5424 + sep + msg3164 + sep

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		WithTrailer(NUL),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 2)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
	assert.Equal(t, auto.FormatRFC3164, auto.DetectFormat(results[1].Message))
}
