package nontransparent

import (
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"github.com/stretchr/testify/assert"
)

func TestNewParserRFC3164WithBestEffort(t *testing.T) {
	res := []syslog.Result{}
	p := NewParserRFC3164(syslog.WithBestEffort(), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))
	assert.True(t, p.HasBestEffort())

	// Parse a valid RFC3164 message with LF trailer
	p.Parse(strings.NewReader("<34>Oct 11 22:14:15 mymachine su: su root failed\n"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
	assert.Nil(t, res[0].Error)
}

func TestNewParserRFC3164WithMachineOptions(t *testing.T) {
	res := []syslog.Result{}
	p := NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))
	assert.True(t, p.HasBestEffort())

	p.Parse(strings.NewReader("<34>Oct 11 22:14:15 mymachine su: su root failed\n"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}

func TestNewParserRFC3164Strict(t *testing.T) {
	res := []syslog.Result{}
	p := NewParserRFC3164(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))
	assert.False(t, p.HasBestEffort())

	p.Parse(strings.NewReader("<34>Oct 11 22:14:15 mymachine su: su root failed\n"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}

func TestNewParserRFC3164MultipleMessages(t *testing.T) {
	res := []syslog.Result{}
	p := NewParserRFC3164(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))

	input := "<34>Oct 11 22:14:15 mymachine su: msg1\n<35>Oct 11 22:14:16 mymachine su: msg2\n"
	p.Parse(strings.NewReader(input))
	assert.Len(t, res, 2)
}

func TestWithMaxMessageLength(t *testing.T) {
	// WithMaxMessageLength is a no-op for nontransparent parser, but should not panic
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {}))
	m := p.(*machine)
	m.WithMaxMessageLength(1024)
	assert.NotNil(t, p)
}

func TestOnEOF(t *testing.T) {
	// OnEOF is a no-op, but should not panic
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {}))
	m := p.(*machine)
	m.OnEOF([]byte("test"))
	m.OnEOF(nil)
}

func TestWithTrailerNUL(t *testing.T) {
	res := []syslog.Result{}
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}), WithTrailer(NUL))

	// NUL-terminated message
	p.Parse(strings.NewReader("<1>1 - - - - - -\x00"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}

func TestWithTrailerNULMultiple(t *testing.T) {
	res := []syslog.Result{}
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}), WithTrailer(NUL))

	p.Parse(strings.NewReader("<1>1 - - - - - -\x00<2>1 - - - - - -\x00"))
	assert.Len(t, res, 2)
}

func TestWithTrailerNULBestEffort(t *testing.T) {
	res := []syslog.Result{}
	p := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}), WithTrailer(NUL))

	p.Parse(strings.NewReader("<1>1 - - - - - -\x00"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}

func TestWithTrailerInvalid(t *testing.T) {
	// Invalid trailer type should be ignored
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {}), WithTrailer(TrailerType(-1)))
	assert.NotNil(t, p)
}

func TestTrailerTypeValueInvalid(t *testing.T) {
	tt := TrailerType(99)
	val, err := tt.Value()
	assert.Equal(t, -1, val)
	assert.Error(t, err)
}

func TestTrailerTypeStringInvalid(t *testing.T) {
	tt := TrailerType(99)
	assert.Equal(t, "", tt.String())
}

func TestNewParserRFC3164WithNULTrailer(t *testing.T) {
	res := []syslog.Result{}
	p := NewParserRFC3164(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}), WithTrailer(NUL))

	p.Parse(strings.NewReader("<34>Oct 11 22:14:15 mymachine su: msg\x00"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}

func TestParseNoTrailerWithBestEffort(t *testing.T) {
	// Message without trailer — should emit via OnCompletion with best effort
	res := []syslog.Result{}
	p := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))

	p.Parse(strings.NewReader("<1>1 - - - - - -"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}

func TestParseNoTrailerStrict(t *testing.T) {
	// Message without trailer in strict mode — should emit error via OnCompletion
	res := []syslog.Result{}
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))

	p.Parse(strings.NewReader("<1>1 - - - - - -"))
	assert.Len(t, res, 1)
	assert.Error(t, res[0].Error)
}

func TestParseInvalidMessage(t *testing.T) {
	res := []syslog.Result{}
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))

	p.Parse(strings.NewReader("not a syslog message\n"))
	assert.Len(t, res, 0)
}

func TestExecNULTrailerWithNULInData(t *testing.T) {
	// Exercise the NUL trailer path in the Exec state machine with data containing NUL bytes
	res := []syslog.Result{}
	p := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}), WithTrailer(NUL))

	// Two messages separated by NUL
	p.Parse(strings.NewReader("<1>1 - - - - - - msg1\x00<2>1 - - - - - - msg2\x00"))
	assert.Len(t, res, 2)
}

func TestExecLFTrailerWithEmbeddedNUL(t *testing.T) {
	// LF trailer with NUL byte in message content
	res := []syslog.Result{}
	p := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))

	p.Parse(strings.NewReader("<1>1 - - - - - - msg\x00content\n"))
	assert.Len(t, res, 1)
}

func TestExecNULTrailerNoTrailingNUL(t *testing.T) {
	// NUL trailer mode but message doesn't end with NUL — should trigger OnCompletion path
	res := []syslog.Result{}
	p := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}), WithTrailer(NUL))

	p.Parse(strings.NewReader("<1>1 - - - - - - msg"))
	assert.Len(t, res, 1)
}

func TestParseRFC3164NoTrailerBestEffort(t *testing.T) {
	res := []syslog.Result{}
	p := NewParserRFC3164(syslog.WithBestEffort(), syslog.WithListener(func(r *syslog.Result) {
		res = append(res, *r)
	}))

	p.Parse(strings.NewReader("<34>Oct 11 22:14:15 mymachine su: msg"))
	assert.Len(t, res, 1)
	assert.NotNil(t, res[0].Message)
}
