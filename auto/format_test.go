package auto

import (
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	"github.com/stretchr/testify/assert"
)

func TestFormat_String(t *testing.T) {
	assert.Equal(t, "rfc3164", FormatRFC3164.String())
	assert.Equal(t, "rfc5424", FormatRFC5424.String())
	assert.Equal(t, "unknown", FormatUnknown.String())
	assert.Equal(t, "unknown", Format(99).String())
}

func TestDetectFormat_RFC3164(t *testing.T) {
	msg := &rfc3164.SyslogMessage{}
	assert.Equal(t, FormatRFC3164, DetectFormat(msg))
}

func TestDetectFormat_RFC5424(t *testing.T) {
	msg := &rfc5424.SyslogMessage{}
	assert.Equal(t, FormatRFC5424, DetectFormat(msg))
}

func TestDetectFormat_Nil(t *testing.T) {
	assert.Equal(t, FormatUnknown, DetectFormat(nil))
}

// mockMessage is an unknown syslog.Message implementation for testing.
type mockMessage struct{ syslog.Base }

func TestDetectFormat_UnknownType(t *testing.T) {
	assert.Equal(t, FormatUnknown, DetectFormat(&mockMessage{}))
}
