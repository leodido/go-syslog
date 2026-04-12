package octetcounting

// Regression tests for https://github.com/leodido/go-syslog/issues/15

import (
	"fmt"
	"strings"
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/stretchr/testify/assert"
)

func TestIssue15_RFC3164_OctetCounting_EmbeddedNewline(t *testing.T) {
	// A single RFC3164 message whose MSG field contains newlines.
	// The octet-counting parser enables WithEmbeddedNewlines automatically.
	msg := "<134>Apr 28 11:53:44 myhost myapp: line1\nline2\nline3"
	input := fmt.Sprintf("%d %s", len(msg), msg)

	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}

	r := strings.NewReader(input)
	NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(acc)).Parse(r)

	if !assert.Len(t, results, 1, "expected exactly one result") {
		return
	}

	res := results[0]
	if !assert.NotNil(t, res.Message, "expected a parsed message, got error: %v", res.Error) {
		return
	}

	sm := res.Message.(*rfc3164.SyslogMessage)
	if !assert.NotNil(t, sm.Message, "expected a non-nil MSG field") {
		return
	}

	assert.Equal(t, "line1\nline2\nline3", *sm.Message,
		"MSG field should preserve embedded newlines")
}

func TestIssue15_RFC3164_OctetCounting_EmbeddedNewline_NoBestEffort(t *testing.T) {
	// Without best effort, the parser should still parse the full message
	// since octet-counting enables WithEmbeddedNewlines automatically.
	msg := "<134>Apr 28 11:53:44 myhost myapp: line1\nline2\nline3"
	input := fmt.Sprintf("%d %s", len(msg), msg)

	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}

	r := strings.NewReader(input)
	NewParserRFC3164(syslog.WithListener(acc)).Parse(r)

	if !assert.Len(t, results, 1, "expected exactly one result") {
		return
	}

	res := results[0]
	if !assert.NotNil(t, res.Message, "expected a parsed message, got error: %v", res.Error) {
		return
	}
	assert.Nil(t, res.Error)

	sm := res.Message.(*rfc3164.SyslogMessage)
	if !assert.NotNil(t, sm.Message, "expected a non-nil MSG field") {
		return
	}

	assert.Equal(t, "line1\nline2\nline3", *sm.Message,
		"MSG field should preserve embedded newlines")
}

func TestIssue15_RFC3164_OctetCounting_MultipleMessages_EmbeddedNewlines(t *testing.T) {
	// Two messages: the first contains embedded newlines, the second is normal.
	// Both should parse correctly.
	msg1 := "<134>Apr 28 11:53:44 myhost myapp: line1\nline2\nline3"
	msg2 := "<134>Apr 28 11:53:45 myhost myapp: hello"
	input := fmt.Sprintf("%d %s%d %s", len(msg1), msg1, len(msg2), msg2)

	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}

	r := strings.NewReader(input)
	NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(acc)).Parse(r)

	if !assert.Len(t, results, 2, "expected two results") {
		return
	}

	// First message: should contain the full multi-line body
	sm1 := results[0].Message.(*rfc3164.SyslogMessage)
	if assert.NotNil(t, sm1.Message) {
		assert.Equal(t, "line1\nline2\nline3", *sm1.Message)
	}

	// Second message: should parse normally
	sm2 := results[1].Message.(*rfc3164.SyslogMessage)
	if assert.NotNil(t, sm2.Message) {
		assert.Equal(t, "hello", *sm2.Message)
	}
}

func TestIssue15_RFC3164_OctetCounting_EmbeddedCR(t *testing.T) {
	// Message with embedded CR (\r) characters.
	msg := "<134>Apr 28 11:53:44 myhost myapp: line1\rline2\rline3"
	input := fmt.Sprintf("%d %s", len(msg), msg)

	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}

	r := strings.NewReader(input)
	NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(acc)).Parse(r)

	if !assert.Len(t, results, 1) {
		return
	}

	sm := results[0].Message.(*rfc3164.SyslogMessage)
	if assert.NotNil(t, sm.Message) {
		assert.Equal(t, "line1\rline2\rline3", *sm.Message)
	}
}

func TestIssue15_RFC3164_OctetCounting_EmbeddedCRLF(t *testing.T) {
	// Message with embedded CRLF (\r\n) sequences.
	msg := "<134>Apr 28 11:53:44 myhost myapp: line1\r\nline2\r\nline3"
	input := fmt.Sprintf("%d %s", len(msg), msg)

	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}

	r := strings.NewReader(input)
	NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(acc)).Parse(r)

	if !assert.Len(t, results, 1) {
		return
	}

	sm := results[0].Message.(*rfc3164.SyslogMessage)
	if assert.NotNil(t, sm.Message) {
		assert.Equal(t, "line1\r\nline2\r\nline3", *sm.Message)
	}
}

func TestIssue15_RFC3164_OctetCounting_TrailingCRLFStripped(t *testing.T) {
	// A trailing \r\n should be stripped (framing convention), but embedded ones preserved.
	msg := "<134>Apr 28 11:53:44 myhost myapp: line1\r\nline2\r\n"
	input := fmt.Sprintf("%d %s", len(msg), msg)

	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}

	r := strings.NewReader(input)
	NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(acc)).Parse(r)

	if !assert.Len(t, results, 1) {
		return
	}

	sm := results[0].Message.(*rfc3164.SyslogMessage)
	if assert.NotNil(t, sm.Message) {
		// Trailing \r\n stripped, embedded \r\n preserved
		assert.Equal(t, "line1\r\nline2", *sm.Message)
	}
}
