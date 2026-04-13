package rfc3195

import (
	"strconv"
	"strings"
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A minimal valid RFC 5424 message
const validRFC5424 = "<1>1 - - - - - -"

// A minimal valid RFC 3164 message
const validRFC3164 = "<34>Oct 11 22:14:15 mymachine su: test"

func TestRawParser_SingleMessage_RFC5424(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	input := beepFrame("ANS", 1, 0, '.', 0, 0, msg1) +
		beepFrame("ANS", 1, 0, '.', seq, 1, msg2) +
		beepFrame("NUL", 1, 0, '.', seq+len(msg2), -1, "")

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
		beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		seqFrame(1, len(payload), 4096) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "") +
		beepFrame("ANS", 1, 0, '.', 0, 1, payload)

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
}

func TestRawParser_EOFWithoutNUL(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload)

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestRawParser_EmptyPayload_OnlyCRLF(t *testing.T) {
	// ANS with only CRLF payload — should be skipped (empty after stripping one CRLF)
	input := beepFrame("ANS", 1, 0, '.', 0, 0, "\r\n") +
		beepFrame("NUL", 1, 0, '.', 2, -1, "")

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	assert.Len(t, results, 0)
}

func TestRawParser_ZeroSizePayload(t *testing.T) {
	input := beepFrame("ANS", 1, 0, '.', 0, 0, "") +
		beepFrame("NUL", 1, 0, '.', 0, -1, "")

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	assert.Len(t, results, 0)
}

func TestRawParser_TrimSuffix_NotTrimRight(t *testing.T) {
	// Payload ending with \r\n\r\n — TrimSuffix strips exactly one CRLF,
	// leaving \r\n which is passed to the syslog parser (and fails).
	// TrimRight would have stripped all trailing CR/LF bytes.
	payload := "not-syslog\r\n\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	// The remaining "not-syslog\r\n" is passed to the parser and fails
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestRawParser_InvalidSyslogMessage_Strict(t *testing.T) {
	payload := "not a syslog message\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	payload := "not a syslog message\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
}

func TestRawParser_MaxMessageLength(t *testing.T) {
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	input := "INVALID\r\n"

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "frame scan error")
}

func TestRawParser_ERRFrameEmitsError(t *testing.T) {
	// ERR frame signals server error — parser should emit error and stop
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		"ERR 1 0 . " + strconv.Itoa(len(payload)) + " 12\r\nserver errorEND\r\n" +
		beepFrame("ANS", 1, 0, '.', len(payload), 1, payload)

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	// First ANS emitted, then ERR terminates — second ANS never reached
	require.Len(t, results, 2)
	assert.NoError(t, results[0].Error)
	assert.ErrorContains(t, results[1].Error, "ERR frame")
	assert.ErrorContains(t, results[1].Error, "server error")
}

func TestRawParser_UnexpectedFrameTypesSkipped(t *testing.T) {
	// MSG and RPY frames are skipped (ERR is handled separately)
	payload := validRFC5424 + "\r\n"
	input := "MSG 0 0 . 0 5\r\nhelloEND\r\n" +
		"RPY 0 0 . 5 2\r\nokEND\r\n" +
		beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

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
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	p := NewParser()
	assert.NotPanics(t, func() {
		p.Parse(strings.NewReader(input))
	})
}

func TestRawParserRFC3164_DefaultListener(t *testing.T) {
	p := NewParserRFC3164()
	payload := validRFC3164 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	assert.NotPanics(t, func() {
		p.Parse(strings.NewReader(input))
	})
}

func TestRawParser_MaxMessageLengthPassedToScanner(t *testing.T) {
	// When maxMessageLength is set, the scanner should reject oversized frames
	// before the RAW parser even sees the payload
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	var results []*syslog.Result
	p := NewParser(
		syslog.WithMaxMessageLength(5),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestRawParser_NoMaxMessageLength(t *testing.T) {
	// When maxMessageLength is 0 (default), scanner uses DefaultMaxPayloadSize
	payload := validRFC5424 + "\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	var results []*syslog.Result
	p := NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

// Verify the parser satisfies syslog.Parser at compile time
var _ syslog.Parser = (*parser)(nil)
