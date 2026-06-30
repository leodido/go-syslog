package rfc5424

import (
	"testing"

	syslogtesting "github.com/leodido/go-syslog/v4/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional test cases to increase coverage of the generated machine.go Parse function
// and the builder.go setWithCtx/translate functions.

var coverageTestCases = []testCase{
	// Valid, message with only whitespace
	{
		[]byte("<1>1 - - - - - - "),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(1),
		"",
		nil,
	},
	// Valid, message with tab character
	{
		[]byte("<1>1 - - - - - - \t"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("\t").SetPriority(1),
		"",
		nil,
	},
	// Valid, message with multiple newlines
	{
		[]byte("<1>1 - - - - - - line1\nline2\nline3"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("line1\nline2\nline3").SetPriority(1),
		"",
		nil,
	},
	// Valid, message with carriage return
	{
		[]byte("<1>1 - - - - - - line1\r\nline2"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("line1\r\nline2").SetPriority(1),
		"",
		nil,
	},
	// Valid, single-char hostname
	{
		[]byte("<1>1 - h - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetHostname("h").SetPriority(1),
		"",
		nil,
	},
	// Valid, single-char appname
	{
		[]byte("<1>1 - - a - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetAppname("a").SetPriority(1),
		"",
		nil,
	},
	// Valid, single-char procid
	{
		[]byte("<1>1 - - - p - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetProcID("p").SetPriority(1),
		"",
		nil,
	},
	// Valid, single-char msgid
	{
		[]byte("<1>1 - - - - m -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMsgID("m").SetPriority(1),
		"",
		nil,
	},
	// Valid, structured data with multiple params in one element
	{
		[]byte(`<1>1 - - - - - [id a="1" b="2" c="3"] msg`),
		true,
		(&SyslogMessage{}).SetVersion(1).
			SetParameter("id", "a", "1").
			SetParameter("id", "b", "2").
			SetParameter("id", "c", "3").
			SetMessage("msg").
			SetPriority(1),
		"",
		nil,
	},
	// Valid, structured data with multiple elements
	{
		[]byte(`<1>1 - - - - - [id1 a="1"][id2 b="2"][id3 c="3"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).
			SetParameter("id1", "a", "1").
			SetParameter("id2", "b", "2").
			SetParameter("id3", "c", "3").
			SetPriority(1),
		"",
		nil,
	},
	// Valid, structured data only (no message)
	{
		[]byte(`<1>1 - - - - - [id1 k="v"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).
			SetParameter("id1", "k", "v").
			SetPriority(1),
		"",
		nil,
	},
	// Valid, with all fields populated
	{
		[]byte(`<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [exampleSDID@32473 iut="3"] BOMAn application event log entry...`),
		true,
		(&SyslogMessage{}).
			SetVersion(1).
			SetTimestamp("2003-10-11T22:14:15.003Z").
			SetHostname("mymachine.example.com").
			SetAppname("evntslog").
			SetProcID("1234").
			SetMsgID("ID47").
			SetParameter("exampleSDID@32473", "iut", "3").
			SetMessage("BOMAn application event log entry...").
			SetPriority(165),
		"",
		nil,
	},
	// Valid, version 999 (max)
	{
		[]byte("<1>999 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(999).SetPriority(1),
		"",
		nil,
	},
	// Valid, priority 191 (max)
	{
		[]byte("<191>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(191),
		"",
		nil,
	},
	// Valid, timestamp with positive offset
	{
		[]byte("<1>1 2003-10-11T22:14:15+05:30 - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2003-10-11T22:14:15+05:30").SetPriority(1),
		"",
		nil,
	},
	// Valid, timestamp with negative offset
	{
		[]byte("<1>1 2003-10-11T22:14:15-05:30 - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2003-10-11T22:14:15-05:30").SetPriority(1),
		"",
		nil,
	},
	// Valid, timestamp with microseconds and Z
	{
		[]byte("<1>1 2003-10-11T22:14:15.123456Z - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2003-10-11T22:14:15.123456Z").SetPriority(1),
		"",
		nil,
	},
	// Valid, timestamp with single digit fractional seconds
	{
		[]byte("<1>1 2003-10-11T22:14:15.1Z - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2003-10-11T22:14:15.1Z").SetPriority(1),
		"",
		nil,
	},
	// Valid, structured data param value with escaped chars
	{
		[]byte(`<1>1 - - - - - [id k="val with \" and \\ and \]"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).
			SetParameter("id", "k", `val with \" and \\ and \]`).
			SetPriority(1),
		"",
		nil,
	},
	// Valid, structured data with @ in id (IANA private enterprise)
	{
		[]byte(`<1>1 - - - - - [myid@12345 k="v"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).
			SetParameter("myid@12345", "k", "v").
			SetPriority(1),
		"",
		nil,
	},
	// Valid, message with null byte
	{
		[]byte("<1>1 - - - - - - \x00"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("\x00").SetPriority(1),
		"",
		nil,
	},
	// Valid, message with high bytes
	{
		[]byte("<1>1 - - - - - - \x80\x81\xff"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("\x80\x81\xff").SetPriority(1),
		"",
		nil,
	},
	// Valid, two-digit version
	{
		[]byte("<1>12 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(12).SetPriority(1),
		"",
		nil,
	},
	// Valid, three-digit version
	{
		[]byte("<1>123 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(123).SetPriority(1),
		"",
		nil,
	},
	// Valid, hostname with dots
	{
		[]byte("<1>1 - my.host.example.com - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetHostname("my.host.example.com").SetPriority(1),
		"",
		nil,
	},
	// Valid, hostname as IPv6
	{
		[]byte("<1>1 - ::1 - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetHostname("::1").SetPriority(1),
		"",
		nil,
	},
	// Valid, numeric procid
	{
		[]byte("<1>1 - - - 12345 - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetProcID("12345").SetPriority(1),
		"",
		nil,
	},
	// Valid, structured data element with no params
	{
		[]byte("<1>1 - - - - - [myid]"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetElementID("myid").SetPriority(1),
		"",
		nil,
	},
	// Valid, message with only BOM
	{
		[]byte("<1>1 - - - - - - " + BOM),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("\ufeff").SetPriority(1),
		"",
		nil,
	},
	// Valid, empty structured data followed by message
	{
		[]byte("<1>1 - - - - - - hello world"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("hello world").SetPriority(1),
		"",
		nil,
	},
	// Valid, priority 0
	{
		[]byte("<0>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(0),
		"",
		nil,
	},
}

// Additional edge cases that exercise more state machine transitions in the generated parser.
// These focus on partial/truncated inputs at various points to hit different error recovery paths.
var edgeCaseTestCases = []testCase{
	// Full timestamp with all fields and message
	{
		[]byte("<1>1 2003-10-11T22:14:15.003Z host app pid mid - msg after full"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2003-10-11T22:14:15.003Z").SetHostname("host").SetAppname("app").SetProcID("pid").SetMsgID("mid").SetMessage("msg after full").SetPriority(1),
		"",
		nil,
	},
	// Timestamp with 6-digit fractional seconds and offset
	{
		[]byte("<1>1 2003-10-11T22:14:15.003000+00:00 - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2003-10-11T22:14:15.003000+00:00").SetPriority(1),
		"",
		nil,
	},
	// Long hostname (printable, 100 chars)
	{
		func() []byte {
			h := make([]byte, 100)
			for i := range h {
				h[i] = 'h'
			}
			return []byte("<1>1 - " + string(h) + " - - - -")
		}(),
		true,
		func() *SyslogMessage {
			h := make([]byte, 100)
			for i := range h {
				h[i] = 'h'
			}
			return (&SyslogMessage{}).SetVersion(1).SetHostname(string(h)).SetPriority(1).(*SyslogMessage)
		}(),
		"",
		nil,
	},
	// Structured data with empty param value
	{
		[]byte(`<1>1 - - - - - [id k=""]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "k", "").SetPriority(1),
		"",
		nil,
	},
	// Structured data with param value containing UTF-8
	{
		[]byte(`<1>1 - - - - - [id k="κόσμε"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "k", "κόσμε").SetPriority(1),
		"",
		nil,
	},
	// Multiple structured data elements with params, followed by message
	{
		[]byte(`<1>1 - - - - - [a x="1"][b y="2"] hello`),
		true,
		(&SyslogMessage{}).SetVersion(1).
			SetParameter("a", "x", "1").
			SetParameter("b", "y", "2").
			SetMessage("hello").
			SetPriority(1),
		"",
		nil,
	},
	// Structured data with long param value
	{
		[]byte(`<1>1 - - - - - [id k="abcdefghijklmnopqrstuvwxyz0123456789"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "k", "abcdefghijklmnopqrstuvwxyz0123456789").SetPriority(1),
		"",
		nil,
	},
	// Message with BOM followed by UTF-8
	{
		[]byte("<1>1 - - - - - - " + BOM + "κόσμε"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("\ufeffκόσμε").SetPriority(1),
		"",
		nil,
	},
	// All printable ASCII in message
	{
		[]byte("<1>1 - - - - - - !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMessage("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~").SetPriority(1),
		"",
		nil,
	},
	// Appname at max length (48 chars)
	{
		[]byte("<1>1 - - aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetAppname("aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff").SetPriority(1),
		"",
		nil,
	},
	// ProcID at max length (128 chars)
	{
		func() []byte {
			pid := make([]byte, 128)
			for i := range pid {
				pid[i] = 'x'
			}
			return []byte("<1>1 - - - " + string(pid) + " - -")
		}(),
		true,
		func() *SyslogMessage {
			pid := make([]byte, 128)
			for i := range pid {
				pid[i] = 'x'
			}
			return (&SyslogMessage{}).SetVersion(1).SetProcID(string(pid)).SetPriority(1).(*SyslogMessage)
		}(),
		"",
		nil,
	},
	// MsgID at max length (32 chars)
	{
		[]byte("<1>1 - - - - abcdefghijklmnopqrstuvwxyz012345 -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetMsgID("abcdefghijklmnopqrstuvwxyz012345").SetPriority(1),
		"",
		nil,
	},
	// Structured data element ID at max length (32 chars)
	{
		[]byte(`<1>1 - - - - - [abcdefghijklmnopqrstuvwxyz012345]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetElementID("abcdefghijklmnopqrstuvwxyz012345").SetPriority(1),
		"",
		nil,
	},
	// Structured data param key at max length (32 chars)
	{
		[]byte(`<1>1 - - - - - [id abcdefghijklmnopqrstuvwxyz012345="v"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "abcdefghijklmnopqrstuvwxyz012345", "v").SetPriority(1),
		"",
		nil,
	},
	// Timestamp at midnight UTC
	{
		[]byte("<1>1 2020-01-01T00:00:00Z - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2020-01-01T00:00:00Z").SetPriority(1),
		"",
		nil,
	},
	// Timestamp at end of day
	{
		[]byte("<1>1 2020-12-31T23:59:59Z - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2020-12-31T23:59:59Z").SetPriority(1),
		"",
		nil,
	},
	// Timestamp with max negative offset
	{
		[]byte("<1>1 2020-01-01T00:00:00-23:59 - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2020-01-01T00:00:00-23:59").SetPriority(1),
		"",
		nil,
	},
	// Timestamp with max positive offset
	{
		[]byte("<1>1 2020-01-01T00:00:00+23:59 - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetTimestamp("2020-01-01T00:00:00+23:59").SetPriority(1),
		"",
		nil,
	},
	// Various priority values to exercise facility/severity computation
	{
		[]byte("<0>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(0),
		"",
		nil,
	},
	{
		[]byte("<8>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(8),
		"",
		nil,
	},
	{
		[]byte("<13>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(13),
		"",
		nil,
	},
	{
		[]byte("<87>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(87),
		"",
		nil,
	},
	{
		[]byte("<190>1 - - - - - -"),
		true,
		(&SyslogMessage{}).SetVersion(1).SetPriority(190),
		"",
		nil,
	},
	// Structured data with escaped backslash in value
	{
		[]byte(`<1>1 - - - - - [id k="a\\b"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "k", `a\\b`).SetPriority(1),
		"",
		nil,
	},
	// Structured data with escaped quote in value
	{
		[]byte(`<1>1 - - - - - [id k="a\"b"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "k", `a\"b`).SetPriority(1),
		"",
		nil,
	},
	// Structured data with escaped bracket in value
	{
		[]byte(`<1>1 - - - - - [id k="a\]b"]`),
		true,
		(&SyslogMessage{}).SetVersion(1).SetParameter("id", "k", `a\]b`).SetPriority(1),
		"",
		nil,
	},
}

func TestMachineParseCoverage(t *testing.T) {
	runTestCases(t, coverageTestCases)
}

func TestMachineParseEdgeCases(t *testing.T) {
	runTestCases(t, edgeCaseTestCases)
}

// Test best-effort parsing of various invalid inputs
func TestBestEffortParsing(t *testing.T) {
	m := NewMachine(WithBestEffort())

	tests := []struct {
		name  string
		input string
	}{
		{"truncated after priority", "<1>"},
		{"truncated after version", "<1>1"},
		{"truncated in timestamp year", "<1>1 2003"},
		{"truncated in timestamp month", "<1>1 2003-10"},
		{"truncated in timestamp day", "<1>1 2003-10-11"},
		{"truncated in timestamp hour", "<1>1 2003-10-11T22"},
		{"truncated in timestamp minute", "<1>1 2003-10-11T22:14"},
		{"truncated in timestamp second", "<1>1 2003-10-11T22:14:15"},
		{"truncated in timestamp frac", "<1>1 2003-10-11T22:14:15.003"},
		{"truncated after timestamp", "<1>1 2003-10-11T22:14:15.003Z"},
		{"truncated after hostname", "<1>1 2003-10-11T22:14:15.003Z host"},
		{"truncated after appname", "<1>1 2003-10-11T22:14:15.003Z host app"},
		{"truncated after procid", "<1>1 2003-10-11T22:14:15.003Z host app 123"},
		{"truncated after msgid", "<1>1 2003-10-11T22:14:15.003Z host app 123 ID"},
		{"truncated in SD element", "<1>1 - - - - - [id"},
		{"truncated in SD param key", "<1>1 - - - - - [id k"},
		{"truncated in SD param value", `<1>1 - - - - - [id k="v`},
		{"truncated after SD", "<1>1 - - - - - [id]"},
		{"empty input", ""},
		{"just angle bracket", "<"},
		{"just priority", "<1"},
		{"priority no close", "<1 "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			msg, _ := m.Parse([]byte(tt.input))
			_ = msg
		})
	}
}

// Test non-best-effort parsing of same invalid inputs returns nil message
func TestStrictParsing(t *testing.T) {
	m := NewMachine()

	tests := []struct {
		name  string
		input string
	}{
		{"truncated after priority", "<1>"},
		{"truncated after version", "<1>1"},
		{"truncated in timestamp", "<1>1 2003-10"},
		{"truncated in SD", "<1>1 - - - - - [id"},
		{"empty input", ""},
		{"just angle bracket", "<"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := m.Parse([]byte(tt.input))
			assert.Nil(t, msg)
			assert.Error(t, err)
		})
	}
}

// Test the builder translate function's default case
func TestBuilderTranslateDefault(t *testing.T) {
	e := entrypoint(-1)
	assert.Equal(t, builderStart, e.translate())
}

// Test builder with various structured data scenarios
func TestBuilderSetParameterWithEscapes(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1)
	// Builder validates param values via Ragel; escaped chars must use proper escaping
	sm.SetParameter("id", "key", `value with spaces and 123`)
	assert.NotNil(t, sm.StructuredData)
	elements := *sm.StructuredData
	assert.Equal(t, `value with spaces and 123`, elements["id"]["key"])
}

func TestBuilderSetParameterInvalidValue(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1)
	// Unescaped ] is invalid in param value — builder sets value to empty string
	sm.SetParameter("id", "key", `bad]value`)
	assert.NotNil(t, sm.StructuredData)
	elements := *sm.StructuredData
	assert.Equal(t, "", elements["id"]["key"])
}

func TestBuilderSetParameterMultipleElements(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1)
	sm.SetParameter("id1", "k1", "v1")
	sm.SetParameter("id2", "k2", "v2")
	sm.SetParameter("id1", "k3", "v3")
	assert.NotNil(t, sm.StructuredData)
	elements := *sm.StructuredData
	assert.Equal(t, "v1", elements["id1"]["k1"])
	assert.Equal(t, "v3", elements["id1"]["k3"])
	assert.Equal(t, "v2", elements["id2"]["k2"])
}

func TestBuilderSetParameterOverwrite(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1)
	sm.SetParameter("id", "key", "val1")
	sm.SetParameter("id", "key", "val2")
	elements := *sm.StructuredData
	// Second set should overwrite
	assert.Equal(t, "val2", elements["id"]["key"])
}

// Test String() with various field combinations
func TestStringWithAllNilOptionalFields(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1)
	s, err := sm.String()
	assert.NoError(t, err)
	assert.Equal(t, "<1>1 - - - - - -", s)
}

func TestStringWithStructuredData(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1)
	sm.SetParameter("id", "key", "val")
	s, err := sm.String()
	assert.NoError(t, err)
	assert.Contains(t, s, `[id key="val"]`)
}

func TestStringInvalid(t *testing.T) {
	sm := &SyslogMessage{}
	// No priority or version set
	_, err := sm.String()
	assert.Error(t, err)
}

func TestStringWithMessage(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1).SetMessage("hello")
	s, err := sm.String()
	assert.NoError(t, err)
	assert.Contains(t, s, " hello")
}

func TestStringWithTimestamp(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(1).SetVersion(1).SetTimestamp("2003-10-11T22:14:15.003Z")
	s, err := sm.String()
	assert.NoError(t, err)
	assert.Contains(t, s, "2003-10-11T22:14:15.003Z")
}

func TestStringWithAllFields(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(165).SetVersion(1).
		SetTimestamp("2003-10-11T22:14:15.003Z").
		SetHostname("mymachine").
		SetAppname("myapp").
		SetProcID("1234").
		SetMsgID("ID47").
		SetMessage("test message")
	s, err := sm.String()
	assert.NoError(t, err)
	assert.Equal(t, "<165>1 2003-10-11T22:14:15.003Z mymachine myapp 1234 ID47 - test message", s)
}

// Test Valid() method
func TestSyslogMessageValid(t *testing.T) {
	sm := &SyslogMessage{}
	assert.False(t, sm.Valid())

	sm.SetVersion(1)
	assert.True(t, sm.Valid())

	sm.SetPriority(1)
	assert.True(t, sm.Valid())

	sm2 := &SyslogMessage{}
	sm2.SetPriority(1)
	assert.False(t, sm2.Valid())

	invalidPriority := uint8(192)
	sm3 := &SyslogMessage{Version: 1}
	sm3.Priority = &invalidPriority
	assert.False(t, sm3.Valid())
}

func TestStringRequiresPriority(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetVersion(1)

	rendered, err := sm.String()

	assert.Empty(t, rendered)
	require.EqualError(t, err, "invalid syslog")
}

// Test parser with CompliantMsg option
func TestParserWithCompliantMsg(t *testing.T) {
	p := NewParser(WithCompliantMsg())
	msg, err := p.Parse([]byte("<1>1 - - - - - - hello"))
	assert.NoError(t, err)
	assert.NotNil(t, msg)
	sm := msg.(*SyslogMessage)
	assert.Equal(t, "hello", *sm.Message)
}

// Test parser concurrent safety
func TestParserConcurrentParse(t *testing.T) {
	p := NewParser(WithBestEffort())
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			msg, err := p.Parse([]byte("<1>1 - - - - - - hello"))
			assert.NoError(t, err)
			assert.NotNil(t, msg)
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test machine Err() after various states
func TestMachineErrAfterValidParse(t *testing.T) {
	m := NewMachine().(*machine)
	_, _ = m.Parse([]byte("<1>1 - - - - - -"))
	assert.Nil(t, m.Err())
}

func TestMachineErrAfterInvalidParse(t *testing.T) {
	m := NewMachine().(*machine)
	_, _ = m.Parse([]byte("invalid"))
	assert.NotNil(t, m.Err())
}

func TestMachineErrResetOnNewParse(t *testing.T) {
	m := NewMachine().(*machine)
	_, _ = m.Parse([]byte("invalid"))
	assert.NotNil(t, m.Err())
	_, _ = m.Parse([]byte("<1>1 - - - - - -"))
	assert.Nil(t, m.Err())
}

// Test builder with invalid inputs
func TestBuilderSetInvalidPriority(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetPriority(192) // out of range
	assert.Nil(t, sm.Priority)
}

func TestBuilderSetInvalidVersion(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetVersion(0) // out of range
	assert.Equal(t, uint16(0), sm.Version)

	sm.SetVersion(1000) // out of range
	assert.Equal(t, uint16(0), sm.Version)
}

func TestBuilderSetInvalidTimestamp(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetTimestamp("not-a-timestamp")
	assert.Nil(t, sm.Timestamp)
}

func TestBuilderSetNilHostname(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetHostname("-")
	assert.Nil(t, sm.Hostname)
}

func TestBuilderSetNilAppname(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetAppname("-")
	assert.Nil(t, sm.Appname)
}

func TestBuilderSetNilProcID(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetProcID("-")
	assert.Nil(t, sm.ProcID)
}

func TestBuilderSetNilMsgID(t *testing.T) {
	sm := &SyslogMessage{}
	sm.SetMsgID("-")
	assert.Nil(t, sm.MsgID)
}

// Test syslogMessage internal methods
func TestSyslogMessageMinimal(t *testing.T) {
	sm := &syslogMessage{}
	assert.False(t, sm.minimal())

	sm.prioritySet = true
	sm.priority = 1
	sm.version = 1
	assert.True(t, sm.minimal())
}

func TestSyslogMessageExport(t *testing.T) {
	sm := &syslogMessage{}
	sm.prioritySet = true
	sm.priority = 34
	sm.version = 1
	sm.hostname = "host"
	sm.appname = "app"
	sm.procID = "123"
	sm.msgID = "ID1"
	sm.message = "hello"

	out := sm.export()
	assert.Equal(t, uint16(1), out.Version)
	assert.Equal(t, "host", *out.Hostname)
	assert.Equal(t, "app", *out.Appname)
	assert.Equal(t, "123", *out.ProcID)
	assert.Equal(t, "ID1", *out.MsgID)
	assert.Equal(t, "hello", *out.Message)
}

func TestSyslogMessageExportNilFields(t *testing.T) {
	sm := &syslogMessage{}
	sm.prioritySet = true
	sm.priority = 1
	sm.version = 1
	sm.hostname = "-"
	sm.appname = "-"
	sm.procID = "-"
	sm.msgID = "-"

	out := sm.export()
	assert.Nil(t, out.Hostname)
	assert.Nil(t, out.Appname)
	assert.Nil(t, out.ProcID)
	assert.Nil(t, out.MsgID)
	assert.Nil(t, out.Message)
	assert.Nil(t, out.StructuredData)
}

func TestSyslogMessageExportWithStructuredData(t *testing.T) {
	sm := &syslogMessage{}
	sm.prioritySet = true
	sm.priority = 1
	sm.version = 1
	sm.hasElements = true
	sm.structuredData = map[string]map[string]string{
		"id": {"key": "val"},
	}

	out := sm.export()
	assert.NotNil(t, out.StructuredData)
	assert.Equal(t, "val", (*out.StructuredData)["id"]["key"])
}

// Test WithBestEffort and WithCompliantMsg options
func TestWithBestEffortOption(t *testing.T) {
	m := NewMachine(WithBestEffort())
	assert.True(t, m.HasBestEffort())
}

func TestWithCompliantMsgOption(t *testing.T) {
	m := NewMachine(WithCompliantMsg()).(*machine)
	assert.True(t, m.compliantMsg)
}

// Test FacilityMessage and SeverityMessage via parsed messages
func TestParsedMessageFacilityAndSeverity(t *testing.T) {
	m := NewMachine()
	msg, err := m.Parse([]byte("<34>1 - - - - - -"))
	assert.NoError(t, err)
	sm := msg.(*SyslogMessage)

	assert.NotNil(t, sm.FacilityMessage())
	assert.NotNil(t, sm.FacilityLevel())
	assert.NotNil(t, sm.SeverityMessage())
	assert.NotNil(t, sm.SeverityLevel())
	assert.NotNil(t, sm.SeverityShortLevel())

	assert.Equal(t, "authorization messages", *sm.FacilityMessage())
	assert.Equal(t, "auth", *sm.FacilityLevel())
}

func TestNilFacilityAndSeverity(t *testing.T) {
	sm := &SyslogMessage{}
	assert.Nil(t, sm.FacilityMessage())
	assert.Nil(t, sm.FacilityLevel())
	assert.Nil(t, sm.SeverityMessage())
	assert.Nil(t, sm.SeverityLevel())
	assert.Nil(t, sm.SeverityShortLevel())
}

// Test builder chaining returns Builder interface
func TestBuilderChaining(t *testing.T) {
	sm := &SyslogMessage{}
	result := sm.SetPriority(1).
		SetVersion(1).
		SetTimestamp("2003-10-11T22:14:15.003Z").
		SetHostname("host").
		SetAppname("app").
		SetProcID("123").
		SetMsgID("ID1").
		SetElementID("sdid").
		SetMessage("hello")

	assert.NotNil(t, result)
	assert.Equal(t, syslogtesting.StringAddress("host"), sm.Hostname)
}
