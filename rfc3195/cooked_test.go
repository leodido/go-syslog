package rfc3195

import (
	"strings"
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Full <entry> with all attributes
const fullEntry = `<entry facility='4' severity='2' timestamp='Oct 11 22:14:15' tag='su' deviceFQDN='mymachine.example.com' deviceIP='10.0.0.1' pathID='173'>'su root' failed for lonvick on /dev/pts/8</entry>`

// Minimal <entry> with only required attributes
const minimalEntry = `<entry facility='0' severity='0'></entry>`

func cookedInput(payloads ...string) string {
	var b strings.Builder
	seq := 0
	for i, p := range payloads {
		b.WriteString(beepFrame("ANS", 1, 0, '.', seq, i, p))
		seq += len(p)
	}
	b.WriteString(beepFrame("NUL", 1, 0, '.', seq, -1, ""))
	return b.String()
}

func TestCookedParser_FullEntry(t *testing.T) {
	input := cookedInput(fullEntry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	require.NotNil(t, results[0].Message)

	msg := results[0].Message.(*CookedMessage)
	assert.True(t, msg.Valid())

	// Priority = 4*8 + 2 = 34
	assert.Equal(t, uint8(34), *msg.Priority)
	assert.Equal(t, uint8(4), *msg.Facility)
	assert.Equal(t, uint8(2), *msg.Severity)

	assert.Equal(t, "su", *msg.Appname)
	assert.Equal(t, "mymachine.example.com", *msg.Hostname)
	assert.Equal(t, "mymachine.example.com", *msg.DeviceFQDN)
	assert.Equal(t, "10.0.0.1", *msg.DeviceIP)
	assert.Equal(t, "173", *msg.PathID)
	assert.Equal(t, "'su root' failed for lonvick on /dev/pts/8", *msg.Message)

	require.NotNil(t, msg.Timestamp)
	assert.Equal(t, 10, int(msg.Timestamp.Month()))
	assert.Equal(t, 11, msg.Timestamp.Day())
	assert.Equal(t, 22, msg.Timestamp.Hour())
	assert.Equal(t, 14, msg.Timestamp.Minute())
	assert.Equal(t, 15, msg.Timestamp.Second())
}

func TestCookedParser_MinimalEntry(t *testing.T) {
	input := cookedInput(minimalEntry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)

	msg := results[0].Message.(*CookedMessage)
	assert.True(t, msg.Valid())
	assert.Equal(t, uint8(0), *msg.Priority)
	assert.Equal(t, uint8(0), *msg.Facility)
	assert.Equal(t, uint8(0), *msg.Severity)
	assert.Nil(t, msg.Timestamp)
	assert.Nil(t, msg.Appname)
	assert.Nil(t, msg.Hostname)
	assert.Nil(t, msg.DeviceFQDN)
	assert.Nil(t, msg.DeviceIP)
	assert.Nil(t, msg.PathID)
	assert.Nil(t, msg.Message)
}

func TestCookedParser_HostnameFromDeviceIP(t *testing.T) {
	// No deviceFQDN, only deviceIP — hostname should come from deviceIP
	entry := `<entry facility='1' severity='3' deviceIP='192.168.1.1'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	msg := results[0].Message.(*CookedMessage)
	assert.Equal(t, "192.168.1.1", *msg.Hostname)
	assert.Nil(t, msg.DeviceFQDN)
	assert.Equal(t, "192.168.1.1", *msg.DeviceIP)
}

func TestCookedParser_HostnameFromDeviceFQDN_Preferred(t *testing.T) {
	// Both deviceFQDN and deviceIP — hostname should come from deviceFQDN
	entry := `<entry facility='1' severity='3' deviceFQDN='host.example.com' deviceIP='10.0.0.1'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	msg := results[0].Message.(*CookedMessage)
	assert.Equal(t, "host.example.com", *msg.Hostname)
}

func TestCookedParser_MultipleEntries(t *testing.T) {
	e1 := `<entry facility='0' severity='0'>msg1</entry>`
	e2 := `<entry facility='1' severity='1'>msg2</entry>`
	input := cookedInput(e1, e2)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 2)
	assert.Equal(t, "msg1", *results[0].Message.(*CookedMessage).Message)
	assert.Equal(t, "msg2", *results[1].Message.(*CookedMessage).Message)
}

func TestCookedParser_PriorityComputation(t *testing.T) {
	// facility=23, severity=7 → priority = 23*8+7 = 191
	entry := `<entry facility='23' severity='7'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	msg := results[0].Message.(*CookedMessage)
	assert.Equal(t, uint8(191), *msg.Priority)
	assert.Equal(t, uint8(23), *msg.Facility)
	assert.Equal(t, uint8(7), *msg.Severity)
}

// Invalid attribute values

func TestCookedParser_InvalidFacility_OutOfRange(t *testing.T) {
	entry := `<entry facility='24' severity='0'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "invalid facility")
	assert.Nil(t, results[0].Message)
}

func TestCookedParser_InvalidFacility_NonNumeric(t *testing.T) {
	entry := `<entry facility='abc' severity='0'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "invalid facility")
}

func TestCookedParser_InvalidSeverity_OutOfRange(t *testing.T) {
	entry := `<entry facility='0' severity='8'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "invalid severity")
	assert.Nil(t, results[0].Message)
}

func TestCookedParser_InvalidSeverity_NonNumeric(t *testing.T) {
	entry := `<entry facility='0' severity='xyz'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "invalid severity")
}

func TestCookedParser_InvalidTimestamp(t *testing.T) {
	entry := `<entry facility='0' severity='0' timestamp='not-a-timestamp'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "invalid timestamp")
	assert.Nil(t, results[0].Message)
}

func TestCookedParser_InvalidXML(t *testing.T) {
	entry := `<entry facility='0' severity='0'>unclosed`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "invalid XML")
}

// Metadata elements

func TestCookedParser_RawElementListener_IAM(t *testing.T) {
	iam := `<iam fqdn='collector.example.com' ip='10.0.0.99' type='collector'>Located in rack 5</iam>`
	input := cookedInput(iam)

	var rawCalls []struct {
		name string
		xml  []byte
	}
	p := NewCookedParser(
		syslog.WithListener(func(r *syslog.Result) {}),
		WithRawElementListener(func(name string, raw []byte) {
			rawCalls = append(rawCalls, struct {
				name string
				xml  []byte
			}{name, raw})
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, rawCalls, 1)
	assert.Equal(t, "iam", rawCalls[0].name)
	assert.Equal(t, []byte(iam), rawCalls[0].xml)
}

func TestCookedParser_RawElementListener_Path(t *testing.T) {
	path := `<path fromFQDN='relay.example.com' fromIP='10.0.0.50' toFQDN='collector.example.com' toIP='10.0.0.99' pathID='173' linkprops='ULRI'></path>`
	input := cookedInput(path)

	var rawCalls []struct {
		name string
		xml  []byte
	}
	p := NewCookedParser(
		syslog.WithListener(func(r *syslog.Result) {}),
		WithRawElementListener(func(name string, raw []byte) {
			rawCalls = append(rawCalls, struct {
				name string
				xml  []byte
			}{name, raw})
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, rawCalls, 1)
	assert.Equal(t, "path", rawCalls[0].name)
}

func TestCookedParser_RawElementListener_OK(t *testing.T) {
	ok := `<ok></ok>`
	input := cookedInput(ok)

	var rawCalls []struct {
		name string
		xml  []byte
	}
	p := NewCookedParser(
		syslog.WithListener(func(r *syslog.Result) {}),
		WithRawElementListener(func(name string, raw []byte) {
			rawCalls = append(rawCalls, struct {
				name string
				xml  []byte
			}{name, raw})
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, rawCalls, 1)
	assert.Equal(t, "ok", rawCalls[0].name)
}

func TestCookedParser_MetadataSkippedWithoutListener(t *testing.T) {
	iam := `<iam fqdn='c.example.com' ip='10.0.0.99' type='collector'/>`
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := cookedInput(iam, entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	// Only the entry should be emitted, iam silently skipped
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, "test", *results[0].Message.(*CookedMessage).Message)
}

func TestCookedParser_UnknownElementSkipped(t *testing.T) {
	unknown := `<foobar attr='val'>content</foobar>`
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := cookedInput(unknown, entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Equal(t, "test", *results[0].Message.(*CookedMessage).Message)
}

// Frame handling

func TestCookedParser_ERRFrame(t *testing.T) {
	entry := `<entry facility='0' severity='0'>msg1</entry>`
	input := beepFrame("ANS", 1, 0, '.', 0, 0, entry) +
		"ERR 1 0 . " + "0 12\r\nserver errorEND\r\n"

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 2)
	assert.NoError(t, results[0].Error)
	assert.ErrorContains(t, results[1].Error, "ERR frame")
}

func TestCookedParser_NULTerminates(t *testing.T) {
	entry := `<entry facility='0' severity='0'>msg1</entry>`
	input := beepFrame("ANS", 1, 0, '.', 0, 0, entry) +
		beepFrame("NUL", 1, 0, '.', len(entry), -1, "") +
		beepFrame("ANS", 1, 0, '.', 0, 1, entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
}

func TestCookedParser_SEQSkipped(t *testing.T) {
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := seqFrame(0, 0, 4096) +
		beepFrame("ANS", 1, 0, '.', 0, 0, entry) +
		seqFrame(1, len(entry), 4096) +
		beepFrame("NUL", 1, 0, '.', len(entry), -1, "")

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestCookedParser_EOFWithoutNUL(t *testing.T) {
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := beepFrame("ANS", 1, 0, '.', 0, 0, entry)

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestCookedParser_FrameScanError(t *testing.T) {
	input := "INVALID\r\n"

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "frame scan error")
}

func TestCookedParser_EmptyPayload(t *testing.T) {
	input := beepFrame("ANS", 1, 0, '.', 0, 0, "") +
		beepFrame("NUL", 1, 0, '.', 0, -1, "")

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	assert.Len(t, results, 0)
}

func TestCookedParser_EmptyStream(t *testing.T) {
	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(""))

	assert.Len(t, results, 0)
}

// Best effort mode

func TestCookedParser_BestEffort_InvalidFacility(t *testing.T) {
	entry := `<entry facility='99' severity='0'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(
		syslog.WithBestEffort(),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.NotNil(t, results[0].Message) // partial message emitted in best-effort
}

func TestCookedParser_BestEffort_InvalidXML(t *testing.T) {
	entry := `<entry facility='0' severity='0'>unclosed`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(
		syslog.WithBestEffort(),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestCookedParser_HasBestEffort(t *testing.T) {
	p := NewCookedParser()
	assert.False(t, p.HasBestEffort())

	p2 := NewCookedParser(syslog.WithBestEffort())
	assert.True(t, p2.HasBestEffort())
}

func TestCookedParser_MaxMessageLength(t *testing.T) {
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := cookedInput(entry)

	var results []*syslog.Result
	p := NewCookedParser(
		syslog.WithMaxMessageLength(5), // too small for the XML
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestCookedParser_DefaultListener(t *testing.T) {
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := cookedInput(entry)

	p := NewCookedParser()
	assert.NotPanics(t, func() {
		p.Parse(strings.NewReader(input))
	})
}

func TestCookedParser_WithMachineOptions(t *testing.T) {
	// WithMachineOptions is a no-op for COOKED (no inner machine),
	// but should not panic
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := cookedInput(entry)

	noopOpt := func(m syslog.Machine) syslog.Machine { return m }

	var results []*syslog.Result
	p := NewCookedParser(
		syslog.WithMachineOptions(noopOpt),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
	)

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestCookedParser_MSGFrame(t *testing.T) {
	// COOKED profile uses MSG frames (not just ANS) per RFC 3195 §4.3
	entry := `<entry facility='0' severity='0'>via MSG</entry>`
	input := "MSG 1 0 . 0 " + strings.Repeat("", 0) +
		beepFrame("MSG", 1, 0, '.', 0, -1, entry)[4:] // reuse beepFrame but it's MSG

	// Actually let's build it properly
	input = beepFrame("MSG", 1, 0, '.', 0, -1, entry) +
		beepFrame("NUL", 1, 0, '.', len(entry), -1, "")

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.Equal(t, "via MSG", *results[0].Message.(*CookedMessage).Message)
}

func TestCookedParser_RPYFrameSkipped(t *testing.T) {
	// RPY frames should be skipped (they carry <ok/> responses in full BEEP)
	entry := `<entry facility='0' severity='0'>test</entry>`
	input := "RPY 0 0 . 0 2\r\nokEND\r\n" +
		beepFrame("ANS", 1, 0, '.', 0, 0, entry) +
		beepFrame("NUL", 1, 0, '.', len(entry), -1, "")

	var results []*syslog.Result
	p := NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(input))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

// Compile-time interface check
var _ syslog.Parser = (*cookedParser)(nil)
