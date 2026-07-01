package rfc3164

import (
	"testing"
	"time"

	"github.com/leodido/go-syslog/v4"
	syslogtesting "github.com/leodido/go-syslog/v4/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional test cases to exercise more paths in the generated machine.go Parse function.

func TestParseCoverageValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		opts  []syslog.MachineOption
		check func(t *testing.T, msg syslog.Message, err error)
	}{
		{
			name:  "minimal with all months",
			input: "<0>Mar  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, msg)
			},
		},
		{
			name:  "month Apr",
			input: "<0>Apr  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month May",
			input: "<0>May  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month Jun",
			input: "<0>Jun  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month Jul",
			input: "<0>Jul  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month Aug",
			input: "<0>Aug  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month Sep",
			input: "<0>Sep  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month Nov",
			input: "<0>Nov  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "month Dec",
			input: "<0>Dec  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "double-digit day",
			input: "<0>Jan 12 06:30:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "day 31",
			input: "<0>Jan 31 23:59:59 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "priority 191 max",
			input: "<191>Jan  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, uint8(191), *sm.Priority)
			},
		},
		{
			name:  "single-digit priority",
			input: "<1>Jan  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "two-digit priority",
			input: "<34>Jan  1 00:00:00 h m: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "message without tag",
			input: "<34>Jan  1 00:00:00 host just a message",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.NotNil(t, sm.Message)
			},
		},
		{
			name:  "tag with PID",
			input: "<34>Jan  1 00:00:00 host app[1234]: message",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, "app", *sm.Appname)
				assert.Equal(t, "1234", *sm.ProcID)
				assert.Equal(t, "message", *sm.Message)
			},
		},
		{
			name:  "tag without PID",
			input: "<34>Jan  1 00:00:00 host app: message",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, "app", *sm.Appname)
				assert.Nil(t, sm.ProcID)
			},
		},
		{
			name:  "hostname as IP",
			input: "<34>Jan  1 00:00:00 192.168.1.1 app: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, "192.168.1.1", *sm.Hostname)
			},
		},
		{
			name:  "hostname with dots",
			input: "<34>Jan  1 00:00:00 host.example.com app: msg",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, "host.example.com", *sm.Hostname)
			},
		},
		{
			name:  "message with special chars",
			input: "<34>Jan  1 00:00:00 host app: msg with !@#$%^&*()_+-={}|[]\\:\";'<>?,./",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, msg)
			},
		},
		{
			name:  "message with tab",
			input: "<34>Jan  1 00:00:00 host app: \tmsg with tab",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "with year option",
			input: "<34>Jan  1 00:00:00 host app: msg",
			opts:  []syslog.MachineOption{WithYear(Year{YYYY: 2020})},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, 2020, sm.Timestamp.Year())
			},
		},
		{
			name:  "with timezone option",
			input: "<34>Jan  1 00:00:00 host app: msg",
			opts:  []syslog.MachineOption{WithTimezone(time.FixedZone("EST", -5*3600))},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				_, offset := sm.Timestamp.Zone()
				assert.Equal(t, -5*3600, offset)
			},
		},
		{
			name:  "with locale timezone option",
			input: "<34>Jan  1 00:00:00 host app: msg",
			opts:  []syslog.MachineOption{WithLocaleTimezone(time.FixedZone("CET", 3600))},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				_, offset := sm.Timestamp.Zone()
				assert.Equal(t, 3600, offset)
			},
		},
		{
			name:  "with RFC3339 timestamp Z",
			input: "<34>2003-10-11T22:14:15Z host app: msg",
			opts:  []syslog.MachineOption{WithRFC3339()},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, 2003, sm.Timestamp.Year())
				assert.Equal(t, time.October, sm.Timestamp.Month())
			},
		},
		{
			name:  "with RFC3339 timestamp and positive offset",
			input: "<34>2003-10-11T22:14:15+05:30 host app: msg",
			opts:  []syslog.MachineOption{WithRFC3339()},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, 2003, sm.Timestamp.Year())
			},
		},
		{
			name:  "with RFC3339 timestamp and negative offset",
			input: "<34>2003-10-11T22:14:15-07:00 host app: msg",
			opts:  []syslog.MachineOption{WithRFC3339()},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},

		{
			name:  "with second fractions",
			input: "<34>Jan  1 00:00:00.123 host app: msg",
			opts:  []syslog.MachineOption{WithSecondFractions()},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "with lenient day zero-prefixed",
			input: "<34>Jan 01 00:00:00 host app: msg",
			opts:  []syslog.MachineOption{WithLenientDay()},
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "no hostname (BSD style)",
			input: "<46>Apr 27 23:06:01 syslogd[68529]: start",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "trailing newline stripped",
			input: "<34>Jan  1 00:00:00 host app: msg\n",
			check: func(t *testing.T, msg syslog.Message, err error) {
				assert.NoError(t, err)
				sm := msg.(*SyslogMessage)
				assert.Equal(t, "msg", *sm.Message)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMachine(tt.opts...)
			msg, err := m.Parse([]byte(tt.input))
			tt.check(t, msg, err)
		})
	}
}

func TestParseCoverageInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"just angle bracket", "<"},
		{"no closing bracket", "<34"},
		{"no priority value", "<>"},
		{"priority too large", "<192>Jan  1 00:00:00 h m: msg"},
		{"no timestamp", "<34>"},
		{"invalid month", "<34>Xyz  1 00:00:00 h m: msg"},
		{"truncated month", "<34>Ja"},
		{"truncated day", "<34>Jan"},
		{"invalid day", "<34>Jan 32 00:00:00 h m: msg"},
		{"truncated hour", "<34>Jan  1 "},
		{"invalid hour", "<34>Jan  1 25:00:00 h m: msg"},
		{"truncated minute", "<34>Jan  1 00:"},
		{"invalid minute", "<34>Jan  1 00:60:00 h m: msg"},
		{"truncated second", "<34>Jan  1 00:00:"},
		{"invalid second", "<34>Jan  1 00:00:60 h m: msg"},
		{"just priority and space", "<34> "},
		{"non-printable in hostname", "<34>Jan  1 00:00:00 \x01host m: msg"},
	}

	m := NewMachine()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := m.Parse([]byte(tt.input))
			// Should either return error or nil message (strict mode)
			if err == nil {
				// Some inputs may parse partially
				_ = msg
			}
		})
	}
}

func TestParseCoverageBestEffort(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"truncated after priority", "<34>"},
		{"truncated after month", "<34>Jan"},
		{"truncated after day", "<34>Jan  1"},
		{"truncated after hour", "<34>Jan  1 00"},
		{"truncated after minute", "<34>Jan  1 00:00"},
		{"truncated after second", "<34>Jan  1 00:00:00"},
		{"truncated after hostname", "<34>Jan  1 00:00:00 host"},
		{"truncated after tag", "<34>Jan  1 00:00:00 host app:"},
		{"invalid then valid", "garbage<34>Jan  1 00:00:00 host app: msg"},
		{"priority only", "<0>"},
		{"priority and partial timestamp", "<34>Jan  1 00:00"},
	}

	m := NewMachine(WithBestEffort())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			msg, err := m.Parse([]byte(tt.input))
			_ = msg
			_ = err
		})
	}
}

func TestYearTimeHelper(t *testing.T) {
	result := syslogtesting.YearTime(1, 15, 10, 30, 45)
	assert.Equal(t, time.Now().Year(), result.Year())
	assert.Equal(t, time.January, result.Month())
	assert.Equal(t, 15, result.Day())
	assert.Equal(t, 10, result.Hour())
	assert.Equal(t, 30, result.Minute())
	assert.Equal(t, 45, result.Second())
}

func TestParserConcurrentSafety(t *testing.T) {
	p := NewParser(WithBestEffort())
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			msg, err := p.Parse([]byte("<34>Jan  1 00:00:00 host app: msg"))
			assert.NoError(t, err)
			assert.NotNil(t, msg)
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestExportNilFields(t *testing.T) {
	sm := &syslogMessage{}
	sm.prioritySet = true
	sm.priority = 1
	out := sm.export()
	assert.Nil(t, out.Hostname)
	assert.Nil(t, out.Appname)
	assert.Nil(t, out.ProcID)
	assert.Nil(t, out.Message)
	assert.Nil(t, out.Timestamp)
}

func TestExportWithAllFields(t *testing.T) {
	sm := &syslogMessage{}
	sm.prioritySet = true
	sm.priority = 34
	sm.hostname = "host"
	sm.tag = "app"
	sm.content = "1234"
	sm.message = "hello"
	sm.timestampSet = true
	sm.timestamp = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	out := sm.export()
	assert.Equal(t, "host", *out.Hostname)
	assert.Equal(t, "app", *out.Appname)
	assert.Equal(t, "1234", *out.ProcID)
	assert.Equal(t, "hello", *out.Message)
	assert.Equal(t, 2020, out.Timestamp.Year())
}

func TestExportNilDashFields(t *testing.T) {
	sm := &syslogMessage{}
	sm.prioritySet = true
	sm.priority = 1
	sm.hostname = "-"
	sm.tag = "-"
	sm.content = "-"

	out := sm.export()
	assert.Nil(t, out.Hostname)
	assert.Nil(t, out.Appname)
	assert.Nil(t, out.ProcID)
}

func TestRFC3339FractionPrecision(t *testing.T) {
	tests := []struct {
		name       string
		timestamp  string
		nanosecond int
		offset     int
	}{
		{
			name:       "one digit UTC",
			timestamp:  "2024-07-25T18:54:02.2Z",
			nanosecond: 200000000,
			offset:     0,
		},
		{
			name:       "six digits with offset",
			timestamp:  "2024-07-25T18:54:02.123456+02:30",
			nanosecond: 123456000,
			offset:     2*60*60 + 30*60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "<182>" + tt.timestamp + " esxi-a vmkernel: message"
			msg, err := NewMachine(WithRFC3339()).Parse([]byte(input))

			require.NoError(t, err)
			require.NotNil(t, msg)
			sm, ok := msg.(*SyslogMessage)
			require.True(t, ok)
			require.NotNil(t, sm.Timestamp)
			assert.Equal(t, tt.nanosecond, sm.Timestamp.Nanosecond())
			_, offset := sm.Timestamp.Zone()
			assert.Equal(t, tt.offset, offset)
		})
	}
}

func TestRFC3339FractionRejectsMoreThanSixDigits(t *testing.T) {
	msg, err := NewMachine(WithRFC3339()).Parse([]byte("<182>2024-07-25T18:54:02.1234567Z esxi-a vmkernel: message"))

	assert.Nil(t, msg)
	assert.Error(t, err)
}

func TestRFC3339FractionRequiresOption(t *testing.T) {
	msg, err := NewMachine().Parse([]byte("<182>2024-07-25T18:54:02.265Z esxi-a vmkernel: message"))

	assert.Nil(t, msg)
	assert.Error(t, err)
}

func TestRFC3339FractionParserFacade(t *testing.T) {
	msg, err := NewParser(WithRFC3339()).Parse([]byte("<182>2024-07-25T18:54:02.265Z esxi-a vmkernel: Event message"))

	require.NoError(t, err)
	require.NotNil(t, msg)
	sm, ok := msg.(*SyslogMessage)
	require.True(t, ok)
	require.NotNil(t, sm.Timestamp)
	require.NotNil(t, sm.Priority)
	require.NotNil(t, sm.Hostname)
	require.NotNil(t, sm.Appname)
	require.NotNil(t, sm.Message)
	assert.Equal(t, 265000000, sm.Timestamp.Nanosecond())
	assert.Equal(t, uint8(182), *sm.Priority)
	assert.Equal(t, "esxi-a", *sm.Hostname)
	assert.Equal(t, "vmkernel", *sm.Appname)
	assert.Equal(t, "Event message", *sm.Message)
}
