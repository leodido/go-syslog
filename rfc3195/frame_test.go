package rfc3195

import (
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameType_String(t *testing.T) {
	tests := []struct {
		ft   FrameType
		want string
	}{
		{FrameMSG, "MSG"},
		{FrameRPY, "RPY"},
		{FrameERR, "ERR"},
		{FrameANS, "ANS"},
		{FrameNUL, "NUL"},
		{FrameSEQ, "SEQ"},
		{FrameType(99), "FrameType(99)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.ft.String())
	}
}

func TestScan_MSG(t *testing.T) {
	input := "MSG 0 1 . 0 11\r\nhello worldEND\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameMSG, f.Type)
	assert.Equal(t, uint32(0), f.Channel)
	assert.Equal(t, uint32(1), f.Msgno)
	assert.False(t, f.More)
	assert.Equal(t, uint32(0), f.Seqno)
	assert.Equal(t, uint32(11), f.Size)
	assert.Equal(t, []byte("hello world"), f.Payload)
}

func TestScan_RPY(t *testing.T) {
	input := "RPY 1 2 . 100 2\r\nokEND\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameRPY, f.Type)
	assert.Equal(t, uint32(1), f.Channel)
	assert.Equal(t, uint32(2), f.Msgno)
	assert.Equal(t, uint32(100), f.Seqno)
	assert.Equal(t, uint32(2), f.Size)
	assert.Equal(t, []byte("ok"), f.Payload)
}

func TestScan_ERR(t *testing.T) {
	input := "ERR 0 0 . 0 5\r\noops!END\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameERR, f.Type)
	assert.Equal(t, uint32(5), f.Size)
	assert.Equal(t, []byte("oops!"), f.Payload)
}

func TestScan_ANS(t *testing.T) {
	input := "ANS 1 0 . 0 4 7\r\ndataEND\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameANS, f.Type)
	assert.Equal(t, uint32(1), f.Channel)
	assert.Equal(t, uint32(0), f.Msgno)
	assert.Equal(t, uint32(4), f.Size)
	assert.Equal(t, uint32(7), f.Ansno)
	assert.Equal(t, []byte("data"), f.Payload)
}

func TestScan_NUL(t *testing.T) {
	input := "NUL 1 0 . 0 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameNUL, f.Type)
	assert.Equal(t, uint32(0), f.Size)
	assert.Equal(t, []byte{}, f.Payload)
}

func TestScan_SEQ(t *testing.T) {
	input := "SEQ 0 512 4096\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameSEQ, f.Type)
	assert.Equal(t, uint32(0), f.Channel)
	assert.Equal(t, uint32(512), f.Ackno)
	assert.Equal(t, uint32(4096), f.Window)
	assert.Nil(t, f.Payload)
}

func TestScan_MoreIndicator(t *testing.T) {
	// '*' means intermediate (more frames follow)
	input := "MSG 0 1 * 0 3\r\nfooEND\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.True(t, f.More)
}

func TestScan_MultipleFrames(t *testing.T) {
	input := "MSG 0 0 . 0 5\r\nhelloEND\r\n" +
		"SEQ 0 5 4096\r\n" +
		"RPY 0 0 . 5 5\r\nworldEND\r\n"
	s := NewScanner(strings.NewReader(input))

	f1, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameMSG, f1.Type)
	assert.Equal(t, []byte("hello"), f1.Payload)

	f2, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameSEQ, f2.Type)
	assert.Equal(t, uint32(5), f2.Ackno)

	f3, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameRPY, f3.Type)
	assert.Equal(t, []byte("world"), f3.Payload)

	_, err = s.Scan()
	assert.ErrorIs(t, err, io.EOF)
}

func TestScan_EOF(t *testing.T) {
	s := NewScanner(strings.NewReader(""))
	_, err := s.Scan()
	assert.ErrorIs(t, err, io.EOF)
}

func TestScan_PayloadWithNewlines(t *testing.T) {
	// Payload containing CRLF — size-delimited, so newlines are part of payload
	payload := "line1\r\nline2\r\n"
	input := "MSG 0 0 . 0 14\r\n" + payload + "END\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, []byte(payload), f.Payload)
}

func TestScan_ZeroSizePayload(t *testing.T) {
	input := "RPY 0 0 . 0 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, uint32(0), f.Size)
	assert.Equal(t, []byte{}, f.Payload)
}

// Error cases

func TestScan_UnknownKeyword(t *testing.T) {
	input := "FOO 0 0 . 0 0\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "unknown frame keyword")
}

func TestScan_MissingCRLF(t *testing.T) {
	// Header terminated with just LF, no CR
	input := "MSG 0 0 . 0 0\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "missing CRLF")
}

func TestScan_EmptyHeader(t *testing.T) {
	input := "\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "empty frame header")
}

func TestScan_InvalidChannel(t *testing.T) {
	input := "MSG abc 0 . 0 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid channel")
}

func TestScan_InvalidMsgno(t *testing.T) {
	input := "MSG 0 abc . 0 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid msgno")
}

func TestScan_InvalidContinuation(t *testing.T) {
	input := "MSG 0 0 x 0 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid continuation")
}

func TestScan_InvalidSeqno(t *testing.T) {
	input := "MSG 0 0 . abc 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid seqno")
}

func TestScan_InvalidSize(t *testing.T) {
	input := "MSG 0 0 . 0 abc\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid size")
}

func TestScan_InvalidAnsno(t *testing.T) {
	input := "ANS 0 0 . 0 0 abc\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid ansno")
}

func TestScan_WrongFieldCount_MSG(t *testing.T) {
	// MSG needs 6 fields, give it 5
	input := "MSG 0 0 . 0\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "requires 6 fields")
}

func TestScan_WrongFieldCount_ANS(t *testing.T) {
	// ANS needs 7 fields, give it 6
	input := "ANS 0 0 . 0 0\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "requires 7 fields")
}

func TestScan_WrongFieldCount_SEQ(t *testing.T) {
	// SEQ needs 4 fields, give it 3
	input := "SEQ 0 512\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "requires 4 fields")
}

func TestScan_SEQ_InvalidAckno(t *testing.T) {
	input := "SEQ 0 abc 4096\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid ackno")
}

func TestScan_SEQ_InvalidWindow(t *testing.T) {
	input := "SEQ 0 512 abc\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid window")
}

func TestScan_SEQ_InvalidChannel(t *testing.T) {
	input := "SEQ abc 512 4096\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid channel")
}

func TestScan_TruncatedPayload(t *testing.T) {
	// Declare size=10 but only provide 3 bytes before EOF
	input := "MSG 0 0 . 0 10\r\nfoo"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "reading payload")
}

func TestScan_MissingENDTrailer(t *testing.T) {
	input := "MSG 0 0 . 0 3\r\nfooXX\r\n\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "expected END trailer")
}

func TestScan_TruncatedENDTrailer(t *testing.T) {
	// Payload is correct but END trailer is truncated
	input := "MSG 0 0 . 0 3\r\nfooEN"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "reading END trailer")
}

func TestScan_InvalidContinuation_MultiChar(t *testing.T) {
	input := "MSG 0 0 .. 0 0\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "invalid continuation")
}

func TestScan_HeaderReadError(t *testing.T) {
	// Partial header with no newline and EOF
	input := "MSG 0 0 . 0 5"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "reading frame header")
}

func TestScan_LargePayload(t *testing.T) {
	payload := strings.Repeat("A", 4096)
	input := "MSG 0 0 . 0 4096\r\n" + payload + "END\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, 4096, len(f.Payload))
	assert.Equal(t, []byte(payload), f.Payload)
}

func TestNewScanner_WithBufioReader(t *testing.T) {
	// Verify that passing a *bufio.Reader doesn't double-wrap
	r := strings.NewReader("SEQ 0 0 4096\r\n")
	br := NewScanner(r)
	f, err := br.Scan()
	require.NoError(t, err)
	assert.Equal(t, FrameSEQ, f.Type)
}

func TestScan_ExtraFieldsOnMSG(t *testing.T) {
	// MSG with 7 fields (extra field) should fail
	input := "MSG 0 0 . 0 0 99\r\nEND\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "requires 6 fields")
}

func TestScan_SEQ_ExtraFields(t *testing.T) {
	input := "SEQ 0 512 4096 extra\r\n"
	s := NewScanner(strings.NewReader(input))
	_, err := s.Scan()
	assert.ErrorContains(t, err, "requires 4 fields")
}

func TestScan_PayloadContainingEND(t *testing.T) {
	// Payload that contains "END\r\n" — size-delimited, so scanner should not be confused
	payload := "END\r\nEND\r\n"
	size := len(payload)
	input := "MSG 0 0 . 0 " + strconv.Itoa(size) + "\r\n" + payload + "END\r\n"
	s := NewScanner(strings.NewReader(input))
	f, err := s.Scan()
	require.NoError(t, err)
	assert.Equal(t, []byte(payload), f.Payload)
}
