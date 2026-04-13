package nontransparent

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/auto"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"github.com/leodido/ragel-machinery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	descr         string
	input         string
	substitute    bool
	results       []syslog.Result
	effortResults []syslog.Result
}

var testCases []testCase

func getParsingError(col int) error {
	return fmt.Errorf("parsing error [col %d]", col)
}

func getTestCases() []testCase {
	return []testCase{
		// note > no error nor message (nil) returned
		// TODO: should this return an EOF error or ...?
		{
			"empty",
			"",
			false,
			[]syslog.Result{},
			[]syslog.Result{},
		},
		{
			"1st ok",
			"<1>1 - - - - - -%[1]s",
			true,
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
			},
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
			},
		},
		{
			"1st ok//notrailer",
			"<3>1 - - - - - -",
			false,
			[]syslog.Result{
				{
					Error: ragel.NewReadingError(io.ErrUnexpectedEOF.Error()),
				},
			},
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(3).SetVersion(1),
				},
			},
		},
		{
			"1st ok/2nd ok",
			"<1>1 - - - - - -%[1]s<2>1 - - - - - -%[1]s",
			true,
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(2).SetVersion(1),
				},
			},
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(2).SetVersion(1),
				},
			},
		},
		{
			"1st ok/2nd ok//notrailer",
			"<1>1 - - - - - -%[1]s<2>1 - - - - - -",
			true,
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Error: ragel.NewReadingError(io.ErrUnexpectedEOF.Error()),
				},
			},
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(2).SetVersion(1),
				},
			},
		},
		{
			"1st ok//incomplete/2nd ok//incomplete",
			"<1>1%[1]s<2>1%[1]s",
			true,
			[]syslog.Result{
				{
					Error: getParsingError(4),
				},
				{
					Error: getParsingError(4),
				},
			},
			[]syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
					Error:   getParsingError(4),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(2).SetVersion(1),
					Error:   getParsingError(4),
				},
			},
		},
		// TODO: complete the test cases
		// {
		// 	"1st ok//incomplete/2nd ok//incomplete",
		// 	"",
		// },
		// {
		// 	"1st ok//incomplete/2nd ok//incomplete",
		// 	"",
		// },
		// {
		// 	"1st ok//incomplete/2nd ok//incomplete",
		// 	"",
		// },
	}
}

func init() {
	testCases = getTestCases()
}

func TestParse(t *testing.T) {
	for _, tc := range testCases {
		tc := tc

		// Test with trailer LF
		var inputWithLF = tc.input
		if tc.substitute {
			lf, _ := LF.Value()
			inputWithLF = fmt.Sprintf(tc.input, string(rune(lf)))
		}
		t.Run(fmt.Sprintf("strict/LF/%s", tc.descr), func(t *testing.T) {
			t.Parallel()

			res := []syslog.Result{}
			strictParser := NewParser(syslog.WithListener(func(r *syslog.Result) {
				res = append(res, *r)
			}))
			strictParser.Parse(strings.NewReader(inputWithLF))

			assert.Equal(t, tc.results, res)
		})
		t.Run(fmt.Sprintf("effort/LF/%s", tc.descr), func(t *testing.T) {
			t.Parallel()

			res := []syslog.Result{}
			effortParser := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
				res = append(res, *r)
			}))
			effortParser.Parse(strings.NewReader(inputWithLF))

			assert.Equal(t, tc.effortResults, res)
		})

		// Test with trailer NUL
		inputWithNUL := tc.input
		if tc.substitute {
			nul, _ := NUL.Value()
			inputWithNUL = fmt.Sprintf(tc.input, string(rune(nul)))
		}
		t.Run(fmt.Sprintf("strict/NL/%s", tc.descr), func(t *testing.T) {
			t.Parallel()

			res := []syslog.Result{}
			strictParser := NewParser(syslog.WithListener(func(r *syslog.Result) {
				res = append(res, *r)
			}), WithTrailer(NUL))
			strictParser.Parse(strings.NewReader(inputWithNUL))

			assert.Equal(t, tc.results, res)
		})
		t.Run(fmt.Sprintf("effort/NL/%s", tc.descr), func(t *testing.T) {
			t.Parallel()

			res := []syslog.Result{}
			effortParser := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
				res = append(res, *r)
			}), WithTrailer(NUL))
			effortParser.Parse(strings.NewReader(inputWithNUL))

			assert.Equal(t, tc.effortResults, res)
		})
	}
}

func TestParserBestEffortCompatibility(t *testing.T) {
	// Test original API works
	p1 := NewParser()
	assert.False(t, p1.HasBestEffort())

	p2 := NewParser(syslog.WithBestEffort())
	assert.True(t, p2.HasBestEffort())

	// Test new API works too
	p3 := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()))
	assert.True(t, p3.HasBestEffort())
}

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
