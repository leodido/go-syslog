package rfc3195

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// beepFrame builds a raw BEEP data frame string.
// For ANS frames, pass ansno >= 0. For other types, ansno is ignored.
func beepFrame(keyword string, channel, msgno int, more byte, seqno, size int, ansno int, payload string) string {
	header := fmt.Sprintf("%s %d %d %c %d %d", keyword, channel, msgno, more, seqno, size)
	if keyword == "ANS" {
		header += " " + strconv.Itoa(ansno)
	}
	return header + "\r\n" + payload + "END\r\n"
}

func seqFrame(channel, ackno, window int) string {
	return fmt.Sprintf("SEQ %d %d %d\r\n", channel, ackno, window)
}

// A minimal valid RFC 5424 message
const validRFC5424 = "<1>1 - - - - - -"

// A minimal valid RFC 3164 message
const validRFC3164 = "<34>Oct 11 22:14:15 mymachine su: test"

func TestRawParser_SingleMessage_RFC5424(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.NotNil(t, results[0].Message)
	assert.True(t, results[0].Message.Valid())
}

func TestRawParser_SingleMessage_RFC3164(t *testing.T) {
	payload := validRFC3164 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParserRFC3164(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.NotNil(t, results[0].Message)
	assert.True(t, results[0].Message.Valid())
}

func TestRawParser_MultipleMessages(t *testing.T) {
	msg1 := "<1>1 - - - - - -\r\n"
	msg2 := "<2>1 - - - - - -\r\n"
	seq := len(msg1)
	input := beepFrame("ANS", 1, 0, '.', 0, len(msg1), 0, msg1) +
		beepFrame("ANS", 1, 0, '.', seq, len(msg2), 1, msg2) +
		"NUL 1 0 . " + strconv.Itoa(seq+len(msg2)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 2)
	for i, r := range results {
		assert.NoError(t, r.Error, "message %d", i)
		assert.NotNil(t, r.Message, "message %d", i)
	}
}

func TestRawParser_SEQFramesSkipped(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	input := seqFrame(0, 0, 4096) +
		beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		seqFrame(1, len(payload), 4096) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestRawParser_NULTerminates(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	// NUL before second ANS — second message should not be emitted
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n" +
		beepFrame("ANS", 1, 0, '.', 0, len(payload), 1, payload)

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
}

func TestRawParser_EOFWithoutNUL(t *testing.T) {
	// Stream ends without NUL — parser should still emit the message
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload)

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestRawParser_EmptyPayload(t *testing.T) {
	// ANS with only CRLF payload — should be skipped (empty after stripping)
	input := beepFrame("ANS", 1, 0, '.', 0, 2, 0, "\r\n") +
		"NUL 1 0 . 2 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	assert.Len(t, results, 0)
}

func TestRawParser_ZeroSizePayload(t *testing.T) {
	// ANS with zero-size payload — should be skipped
	input := beepFrame("ANS", 1, 0, '.', 0, 0, 0, "") +
		"NUL 1 0 . 0 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	assert.Len(t, results, 0)
}

func TestRawParser_InvalidSyslogMessage_Strict(t *testing.T) {
	// Invalid syslog message (no priority) — strict mode should emit error only
	payload := "not a syslog message\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.Nil(t, results[0].Message)
}

func TestRawParser_InvalidSyslogMessage_BestEffort(t *testing.T) {
	// Invalid syslog message with best effort — should emit partial result
	payload := "not a syslog message\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(
		syslog.WithBestEffort(),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	// Best effort still emits the result (with error)
}

func TestRawParser_MaxMessageLength(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(
		syslog.WithMaxMessageLength(5), // too small
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "exceeds max")
}

func TestRawParser_FrameScanError(t *testing.T) {
	// Malformed frame header
	input := "INVALID\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "frame scan error")
}

func TestRawParser_UnexpectedFrameTypesSkipped(t *testing.T) {
	// MSG and RPY frames should be skipped, only ANS processed
	payload := validRFC5424 + "\r\n"
	input := "MSG 0 0 . 0 5\r\nhelloEND\r\n" +
		"RPY 0 0 . 5 2\r\nokEND\r\n" +
		beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestRawParser_EmptyStream(t *testing.T) {
	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(""))

	assert.Len(t, results, 0)
}

func TestRawParser_HasBestEffort(t *testing.T) {
	p := NewParser()
	assert.False(t, p.HasBestEffort())

	p2 := NewParser(syslog.WithBestEffort())
	assert.True(t, p2.HasBestEffort())
}

func TestRawParserRFC3164_HasBestEffort(t *testing.T) {
	p := NewParserRFC3164()
	assert.False(t, p.HasBestEffort())

	p2 := NewParserRFC3164(syslog.WithBestEffort())
	assert.True(t, p2.HasBestEffort())
}

func TestRawParser_WithMachineOptions(t *testing.T) {
	// Verify that machine options are passed through via WithMachineOptions
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	noopOpt := func(m syslog.Machine) syslog.Machine { return m }

	var results []*syslog.Result
	p := NewParser(
		syslog.WithMachineOptions(noopOpt),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestRawParser_DefaultListener(t *testing.T) {
	// Verify default noop listener doesn't panic
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	p := NewParser()
	assert.NotPanics(t, func() {
		p.Parse(strings.NewReader(input))
	})
}

func TestRawParserRFC3164_DefaultListener(t *testing.T) {
	p := NewParserRFC3164()
	payload := validRFC3164 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, len(payload), 0, payload) +
		"NUL 1 0 . " + strconv.Itoa(len(payload)) + " 0\r\nEND\r\n"

	assert.NotPanics(t, func() {
		p.Parse(strings.NewReader(input))
	})
}

// Verify the parser satisfies syslog.Parser at compile time
var _ syslog.Parser = (*parser)(nil)
