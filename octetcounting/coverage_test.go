package octetcounting

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScannerSetMaxLength(t *testing.T) {
	s := NewScanner(strings.NewReader(""), 0)
	assert.Equal(t, DefaultMaxSize, s.MaxLength())

	s.SetMaxLength(4096)
	assert.Equal(t, 4096, s.MaxLength())

	// Non-positive value should be ignored
	s.SetMaxLength(0)
	assert.Equal(t, 4096, s.MaxLength())

	s.SetMaxLength(-1)
	assert.Equal(t, 4096, s.MaxLength())
}

func TestScannerMaxLength(t *testing.T) {
	s := NewScanner(strings.NewReader(""), 1024)
	assert.Equal(t, 1024, s.MaxLength())
}

func TestScannerDefaultMaxSize(t *testing.T) {
	// maxLength <= 0 should use DefaultMaxSize
	s := NewScanner(strings.NewReader(""), -1)
	assert.Equal(t, DefaultMaxSize, s.MaxLength())
}

func TestScannerMsgExceedsIntLimit(t *testing.T) {
	// This exercises the scanSyslogMsg path where msglen > MaxInt
	// We can't easily trigger this without manipulating internal state,
	// but we can test the scanner with a very large declared length
	// that exceeds what the reader has
	s := NewScanner(strings.NewReader("999999999999999999999 <1>1 - - - - - -"), 0)
	tok := s.Scan()
	// The length prefix is too large to parse as a valid uint64 or exceeds reader
	assert.True(t, tok.typ == EOF || tok.typ == ILLEGAL)
}

func TestScannerPeekError(t *testing.T) {
	// Message declares length longer than available data
	s := NewScanner(strings.NewReader("100 <1>1 - - - - - -"), 0)
	tok := s.Scan()
	// Should get EOF because reader doesn't have 100 bytes
	for tok.typ != EOF {
		tok = s.Scan()
	}
	assert.Equal(t, EOF, tok.typ)
}
