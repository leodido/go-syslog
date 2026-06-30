package rfc5424

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const prioritylessRFC5424 = "1 2023-04-05T16:20:56Z loki.example.com su - ID47 - some message"

func TestOptionalPriorityIsDisabledByDefault(t *testing.T) {
	msg, err := NewMachine().Parse([]byte(prioritylessRFC5424))

	assert.Nil(t, msg)
	require.EqualError(t, err, fmt.Sprintf(ErrPri+ColumnPositionTemplate, 0))
}

func TestOptionalPriorityDoesNotAcceptMalformedPresentPriority(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte("<abc>" + prioritylessRFC5424))

	assert.Nil(t, msg)
	assert.Error(t, err)
}

func TestOptionalPriorityParsesPrioritylessMessage(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte(prioritylessRFC5424))

	require.NoError(t, err)
	require.NotNil(t, msg)

	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	assert.True(t, sm.Valid())
	assert.Nil(t, sm.Priority)
	assert.Nil(t, sm.Facility)
	assert.Nil(t, sm.Severity)
	assert.Equal(t, uint16(1), sm.Version)
	require.NotNil(t, sm.Hostname)
	require.NotNil(t, sm.Appname)
	require.NotNil(t, sm.MsgID)
	require.NotNil(t, sm.Message)
	assert.Equal(t, "loki.example.com", *sm.Hostname)
	assert.Equal(t, "su", *sm.Appname)
	assert.Equal(t, "ID47", *sm.MsgID)
	assert.Equal(t, "some message", *sm.Message)
}

func TestOptionalPriorityParserFacade(t *testing.T) {
	msg, err := NewParser(WithOptionalPriority()).Parse([]byte(prioritylessRFC5424))

	require.NoError(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	assert.Nil(t, sm.Priority)
}

func TestOptionalPriorityPreservesPresentPriority(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte("<34>" + prioritylessRFC5424))

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

func TestOptionalPriorityBestEffortReturnsValidPartial(t *testing.T) {
	msg, err := NewMachine(
		WithOptionalPriority(),
		WithBestEffort(),
	).Parse([]byte("1 -"))

	require.Error(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	assert.True(t, sm.Valid())
	assert.Nil(t, sm.Priority)
}

func TestOptionalPriorityParsedMessageCannotBeSerialized(t *testing.T) {
	msg, err := NewMachine(WithOptionalPriority()).Parse([]byte(prioritylessRFC5424))
	require.NoError(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)

	rendered, err := sm.String()

	assert.Empty(t, rendered)
	require.EqualError(t, err, "invalid syslog")
}
