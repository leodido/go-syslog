package rfc5424

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func FuzzParameterEscaping(f *testing.F) {
	for _, r := range []string{
		``,
		`{"escape\x20me": [""]}`,
		`хлеб`,    // test unicode
		`🇺🇬👁️‍🗨️`, // test grapheme cluster
	} {
		f.Add(r)
	}

	f.Fuzz(func(t *testing.T, payload string) {
		msg := new(SyslogMessage)
		msg.SetPriority(1)
		msg.SetVersion(1)
		msg.SetTimestamp(time.Now().Format(time.RFC3339))
		msg.SetMessage("hello")
		msg.SetParameter("general@0", "payload", payload)

		data, err := msg.String()
		require.NoError(t, err)

		parsed, err := NewParser().Parse([]byte(data))
		require.NoError(t, err)
		require.Equal(t, msg, parsed)
	})
}
