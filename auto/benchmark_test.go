package auto

import (
	"testing"

	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

var (
	benchRFC5424 = []byte(`<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`)
	benchRFC3164 = []byte(`<13>Dec  2 16:31:03 host app: Test message for benchmarking`)
	benchGarbage = []byte(`<34>1 not-a-valid-anything-at-all`)
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

// BenchmarkAutoDetect_Fallback measures the cost when peek guesses wrong
// and fallback triggers (two parse attempts, both fail).
func BenchmarkAutoDetect_Fallback(b *testing.B) {
	m := NewMachine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Parse(benchGarbage)
	}
}
