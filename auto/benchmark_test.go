package auto

import (
	"testing"

	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

var (
	benchRFC5424             = []byte(`<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`)
	benchRFC3164             = []byte(`<13>Dec  2 16:31:03 host app: Test message for benchmarking`)
	benchPrioritylessRFC5424 = []byte(`1 2018-10-11T22:14:15.003Z mymach.it e - 1 - message`)
	benchPrioritylessRFC3164 = []byte(`Dec  2 16:31:03 host app: Test message for benchmarking`)
	benchGarbage             = []byte(`<34>1 not-a-valid-anything-at-all`)
)

// BenchmarkPeekOnly measures the peek detection function in isolation.
func BenchmarkPeekOnly_RFC5424(b *testing.B) {
	for i := 0; i < b.N; i++ {
		detect(benchRFC5424)
	}
}

func BenchmarkPeekOnly_RFC3164(b *testing.B) {
	for i := 0; i < b.N; i++ {
		detect(benchRFC3164)
	}
}

func BenchmarkPeekOnly_PrioritylessRFC5424(b *testing.B) {
	for i := 0; i < b.N; i++ {
		detect(benchPrioritylessRFC5424)
	}
}

func BenchmarkPeekOnly_PrioritylessRFC3164(b *testing.B) {
	for i := 0; i < b.N; i++ {
		detect(benchPrioritylessRFC3164)
	}
}

// BenchmarkAutoDetect measures auto-detect parse (detection + inner machine).
func BenchmarkAutoDetect_RFC5424(b *testing.B) {
	m := NewMachine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchRFC5424)
	}
}

func BenchmarkAutoDetect_RFC3164(b *testing.B) {
	m := NewMachine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchRFC3164)
	}
}

// BenchmarkDirect measures direct machine parse (no auto-detection overhead).
func BenchmarkDirect_RFC5424(b *testing.B) {
	m := rfc5424.NewMachine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchRFC5424)
	}
}

func BenchmarkDirect_RFC3164(b *testing.B) {
	m := rfc3164.NewMachine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchRFC3164)
	}
}

// BenchmarkAutoDetect_AllFail measures the worst-case path when no parser
// succeeds: detect + strict primary fail + strict fallback fail + ParseError
// allocation with defensive copy.
func BenchmarkAutoDetect_AllFail(b *testing.B) {
	m := NewMachine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchGarbage)
	}
}

// BenchmarkAutoDetect_BestEffort measures the cost of best-effort recovery:
// detect + strict primary fail + strict fallback fail + best-effort primary
// returns partial result.
func BenchmarkAutoDetect_BestEffort(b *testing.B) {
	m := NewMachine(WithRFC5424Options(rfc5424.WithBestEffort()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchGarbage)
	}
}
