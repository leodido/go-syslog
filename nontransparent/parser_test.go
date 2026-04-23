package nontransparent

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"github.com/leodido/ragel-machinery"
	"github.com/stretchr/testify/assert"
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


