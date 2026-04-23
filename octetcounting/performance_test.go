package octetcounting

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc5424"
	syslogtesting "github.com/leodido/go-syslog/v4/testing"
)

// This is here to avoid compiler optimizations that
// could remove the actual call we are benchmarking
// during benchmarks
var benchParseResult syslog.Message

type benchCase struct {
	input     []byte
	label     string
	maxLength int
}

var benchCases = []benchCase{
	{
		label: "Small Message Size",
		input: []byte("48 <1>1 2003-10-11T22:14:15.003Z host.local - - - -25 <3>1 - host.local - - - -38 <2>1 - host.local su - - - κόσμε"),
	},
	{
		label: "Default Max Message Size",
		input: []byte(fmt.Sprintf(
			"8192 <%d>%d %s %s %s %s %s - %s",
			syslogtesting.MaxPriority,
			syslogtesting.MaxVersion,
			syslogtesting.MaxRFC3339MicroTimestamp,
			string(syslogtesting.MaxHostname),
			string(syslogtesting.MaxAppname),
			string(syslogtesting.MaxProcID),
			string(syslogtesting.MaxMsgID),
			string(syslogtesting.MaxMessage),
		)),
	},
	{
		label: "UDP Max Message Size",
		input: []byte(fmt.Sprintf(
			"65529 <%d>%d %s %s %s %s %s - %s",
			syslogtesting.MaxPriority,
			syslogtesting.MaxVersion,
			syslogtesting.MaxRFC3339MicroTimestamp,
			string(syslogtesting.MaxHostname),
			string(syslogtesting.MaxAppname),
			string(syslogtesting.MaxProcID),
			string(syslogtesting.MaxMsgID),
			string(syslogtesting.LongerMaxMessage),
		)),
		maxLength: 65529,
	},
}

func BenchmarkParse(b *testing.B) {
	for _, tc := range benchCases {
		tc := tc
		if tc.maxLength == 0 {
			tc.maxLength = 8192
		}
		m := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()))
		b.Run(syslogtesting.RightPad(tc.label, 50), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(tc.input)
				m.Parse(reader)
			}
		})
	}
}

func BenchmarkParseAuto(b *testing.B) {
	rfc5424Msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`
	rfc3164Msg := `<13>Dec  2 16:31:03 host app: Test message`

	cases := []struct {
		label string
		input string
	}{
		{"RFC5424", fmt.Sprintf("%d %s", len(rfc5424Msg), rfc5424Msg)},
		{"RFC3164", fmt.Sprintf("%d %s", len(rfc3164Msg), rfc3164Msg)},
		{"Mixed", fmt.Sprintf("%d %s%d %s", len(rfc5424Msg), rfc5424Msg, len(rfc3164Msg), rfc3164Msg)},
	}

	for _, tc := range cases {
		tc := tc // TODO: remove when dropping Go 1.21 (loop var scoping, go.dev/blog/loopvar-preview)
		b.Run("Auto/"+tc.label, func(b *testing.B) {
			p := NewParserAuto(
				syslog.WithListener(func(*syslog.Result) {}),
				syslog.WithBestEffort(),
			)
			for i := 0; i < b.N; i++ {
				p.Parse(strings.NewReader(tc.input))
			}
		})
	}

	// Direct NewParser for comparison (RFC 5424 only).
	b.Run("Direct/RFC5424", func(b *testing.B) {
		p := NewParser(
			syslog.WithListener(func(*syslog.Result) {}),
			syslog.WithMachineOptions(rfc5424.WithBestEffort()),
		)
		input := fmt.Sprintf("%d %s", len(rfc5424Msg), rfc5424Msg)
		for i := 0; i < b.N; i++ {
			p.Parse(strings.NewReader(input))
		}
	})
}

