package rfc3164

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const prioritylessRFC3164 = "Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"

func TestOptionalPriorityIsDisabledByDefault(t *testing.T) {
	msg, err := NewMachine().Parse([]byte(prioritylessRFC3164))

	assert.Nil(t, msg)
	require.EqualError(t, err, "expecting a priority value within angle brackets [col 0]")
}

func TestOptionalPriorityDoesNotAcceptMalformedPresentPriority(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte("<abc>" + prioritylessRFC3164))

	assert.Nil(t, msg)
	assert.Error(t, err)
}

func TestOptionalPriorityDoesNotEnableCiscoPrefixes(t *testing.T) {
	msg, err := NewMachine(
		WithOptionalPriority(),
		WithMessageCounter(),
	).Parse([]byte("123: " + prioritylessRFC3164))

	assert.Nil(t, msg)
	assert.Error(t, err)
}

func TestOptionalPriorityRestoresCiscoOptionsAfterPrioritylessParse(t *testing.T) {
	m := NewMachine(
		WithOptionalPriority(),
		WithMessageCounter(),
	)

	msg, err := m.Parse([]byte(prioritylessRFC3164))
	require.NoError(t, err)
	require.NotNil(t, msg)

	msg, err = m.Parse([]byte("<34>123: " + prioritylessRFC3164))
	require.NoError(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	require.NotNil(t, sm.MessageCounter)
	assert.Equal(t, uint32(123), *sm.MessageCounter)
}

func TestOptionalPriorityParsesPrioritylessMessage(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte(prioritylessRFC3164))

	require.NoError(t, err)
	require.NotNil(t, msg)

	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	assert.True(t, sm.Valid())
	assert.Nil(t, sm.Priority)
	assert.Nil(t, sm.Facility)
	assert.Nil(t, sm.Severity)
	require.NotNil(t, sm.Hostname)
	require.NotNil(t, sm.Appname)
	require.NotNil(t, sm.Message)
	assert.Equal(t, "mymachine", *sm.Hostname)
	assert.Equal(t, "su", *sm.Appname)
	assert.Equal(t, "'su root' failed for lonvick on /dev/pts/8", *sm.Message)
}

func TestOptionalPriorityParserFacade(t *testing.T) {
	msg, err := NewParser(WithOptionalPriority()).Parse([]byte(prioritylessRFC3164))

	require.NoError(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	assert.Nil(t, sm.Priority)
}

func TestOptionalPriorityPreservesPresentPriority(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte("<34>" + prioritylessRFC3164))

	require.NoError(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	require.NotNil(t, sm.Priority)
	require.NotNil(t, sm.Facility)
	require.NotNil(t, sm.Severity)
	assert.Equal(t, uint8(34), *sm.Priority)
	assert.Equal(t, uint8(4), *sm.Facility)
	assert.Equal(t, uint8(2), *sm.Severity)
	assert.True(t, sm.Valid())
}

func TestSyslogMessageValidWithoutPriority(t *testing.T) {
	timestamp := time.Date(2026, time.June, 30, 12, 0, 0, 0, time.UTC)
	message := "message"

	assert.False(t, (&SyslogMessage{}).Valid())

	timestampOnly := &SyslogMessage{}
	timestampOnly.Timestamp = &timestamp
	assert.False(t, timestampOnly.Valid())

	messageOnly := &SyslogMessage{}
	messageOnly.Message = &message
	assert.False(t, messageOnly.Valid())

	sm := &SyslogMessage{}
	sm.Timestamp = &timestamp
	sm.Message = &message

	assert.True(t, sm.Valid())
}

func TestSyslogMessageRejectsInvalidPresentPriority(t *testing.T) {
	priority := uint8(192)
	timestamp := time.Date(2026, time.June, 30, 12, 0, 0, 0, time.UTC)
	message := "message"

	sm := &SyslogMessage{}
	sm.Priority = &priority
	sm.Timestamp = &timestamp
	sm.Message = &message

	assert.False(t, sm.Valid())
}
