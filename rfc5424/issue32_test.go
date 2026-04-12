package rfc5424

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIssue32_SetMsgID attempts to reproduce https://github.com/leodido/go-syslog/issues/32
// where SetMsgID() allegedly leaves MsgID as nil.
func TestIssue32_SetMsgID(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		m := &SyslogMessage{}
		m.SetMsgID("myid")
		assert.NotNil(t, m.MsgID, "MsgID should not be nil after SetMsgID")
		assert.Equal(t, "myid", *m.MsgID)
	})

	t.Run("single char", func(t *testing.T) {
		m := &SyslogMessage{}
		m.SetMsgID("1")
		assert.NotNil(t, m.MsgID)
		assert.Equal(t, "1", *m.MsgID)
	})

	t.Run("max length 32 chars", func(t *testing.T) {
		m := &SyslogMessage{}
		id := "abcdefghijklmnopqrstuvwxyz012345"
		assert.Len(t, id, 32)
		m.SetMsgID(id)
		assert.NotNil(t, m.MsgID)
		assert.Equal(t, id, *m.MsgID)
	})

	t.Run("too long is rejected", func(t *testing.T) {
		m := &SyslogMessage{}
		id := "abcdefghijklmnopqrstuvwxyz0123456" // 33 chars
		m.SetMsgID(id)
		assert.Nil(t, m.MsgID, "MsgID longer than 32 chars should be rejected")
	})

	t.Run("chained with other setters", func(t *testing.T) {
		m := &SyslogMessage{}
		m.SetPriority(165).SetVersion(1).SetMsgID("myid")
		assert.NotNil(t, m.MsgID, "MsgID should not be nil after chained SetMsgID")
		assert.Equal(t, "myid", *m.MsgID)
	})

	t.Run("via Builder interface", func(t *testing.T) {
		var b Builder = &SyslogMessage{}
		b.SetPriority(165).SetVersion(1).SetMsgID("myid")
		sm := b.(*SyslogMessage)
		assert.NotNil(t, sm.MsgID)
		assert.Equal(t, "myid", *sm.MsgID)
	})

	t.Run("serialization round-trip", func(t *testing.T) {
		m := &SyslogMessage{}
		m.SetPriority(165)
		m.SetVersion(1)
		m.SetTimestamp("2018-10-11T22:14:15.003Z")
		m.SetHostname("mymach.it")
		m.SetAppname("myapp")
		m.SetMsgID("myid")
		m.SetMessage("test message")

		str, err := m.String()
		assert.Nil(t, err)
		assert.Contains(t, str, "myid")

		p := NewParser()
		parsed, perr := p.Parse([]byte(str))
		assert.Nil(t, perr)
		assert.NotNil(t, parsed)

		sm := parsed.(*SyslogMessage)
		assert.NotNil(t, sm.MsgID, "MsgID should survive serialization round-trip")
		assert.Equal(t, "myid", *sm.MsgID)
	})

	t.Run("special characters", func(t *testing.T) {
		m := &SyslogMessage{}
		// MSGID allows printable ASCII 33-126 except spaces
		m.SetMsgID("#1")
		assert.NotNil(t, m.MsgID)
		assert.Equal(t, "#1", *m.MsgID)

		m2 := &SyslogMessage{}
		m2.SetMsgID("msg-id_123")
		assert.NotNil(t, m2.MsgID)
		assert.Equal(t, "msg-id_123", *m2.MsgID)
	})

	t.Run("invalid with space is rejected", func(t *testing.T) {
		m := &SyslogMessage{}
		m.SetMsgID("white space not possible")
		assert.Nil(t, m.MsgID, "MsgID with spaces should be rejected")
	})
}
