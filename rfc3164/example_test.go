package rfc3164

import (
	"fmt"
	"log"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/leodido/go-syslog/v4/ciscoios"
)

func init() {
	spew.Config.DisableCapacities = true
	spew.Config.DisablePointerAddresses = true
}

func output(out interface{}) {
	spew.Dump(out)
}

func Example() {
	i := []byte(`<13>Dec  2 16:31:03 host app: Test`)
	p := NewParser()
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(1),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(13),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(0000-12-02 16:31:03 +0000 UTC),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_readme() {
	p := NewParser()
	msg, err := p.Parse([]byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed"))
	if err != nil {
		log.Fatal(err)
	}

	// Access parsed fields
	fmt.Printf("Priority: %d\n", *msg.(*SyslogMessage).Priority)
	fmt.Printf("Hostname: %s\n", *msg.(*SyslogMessage).Hostname)
	fmt.Printf("Message: %s\n", *msg.(*SyslogMessage).Message)

	// Output:
	// Priority: 34
	// Hostname: mymachine
	// Message: 'su root' failed
}

func Example_currentyear() {
	i := []byte(`<13>Dec  2 16:31:03 host app: Test`)
	p := NewParser(WithYear(CurrentYear{}))
	m, _ := p.Parse(i)
	// Force year to match the one in the comment below
	x, _ := m.(*SyslogMessage)
	x.Timestamp = func(t1 *time.Time) *time.Time {
		currentY := time.Now().Year()
		t2 := t1.AddDate(2021-currentY, 0, 0)

		return &t2
	}(x.Timestamp)

	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(1),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(13),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2021-12-02 16:31:03 +0000 UTC),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_withtimezone() {
	cet := time.FixedZone("CET", 60*60)
	i := []byte(`<13>Jan 30 02:08:03 host app: Test`)
	p := NewParser(WithTimezone(cet))
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(1),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(13),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(0000-01-30 03:08:03 +0100 CET),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_withlocaletimezone() {
	pst, _ := time.LoadLocation("America/New_York")
	i := []byte(`<13>Nov 22 17:09:42 xxx kernel: [118479565.921459] EXT4-fs warning (device sda8): ext4_dx_add_entry:2006: Directory index full!`)
	p := NewParser(WithLocaleTimezone(pst))
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(1),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(13),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(0000-11-22 17:09:42 -0456 LMT),
	//   Hostname: (*string)((len=3) "xxx"),
	//   Appname: (*string)((len=6) "kernel"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=95) "[118479565.921459] EXT4-fs warning (device sda8): ext4_dx_add_entry:2006: Directory index full!")
	//  }
	// })
}

func Example_withtimezone_and_year() {
	est, _ := time.LoadLocation("EST")
	i := []byte(`<13>Jan 30 02:08:03 host app: Test`)
	p := NewParser(WithTimezone(est), WithYear(Year{YYYY: 1987}))
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(1),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(13),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(1987-01-29 21:08:03 -0500 EST),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_besteffort() {
	i := []byte(`<13>Dec  2 16:31:03 -`)
	p := NewParser(WithBestEffort())
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(1),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(13),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(0000-12-02 16:31:03 +0000 UTC),
	//   Hostname: (*string)(<nil>),
	//   Appname: (*string)(<nil>),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=1) "-")
	//  }
	// })
}

func Example_rfc3339timestamp() {
	i := []byte(`<28>2019-12-02T16:49:23+02:00 host app[23410]: Test`)
	p := NewParser(WithRFC3339())
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(3),
	//   Severity: (*uint8)(4),
	//   Priority: (*uint8)(28),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2019-12-02 16:49:23 +0200 +0200),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)((len=5) "23410"),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_stamp_also_when_rfc3339() {
	i := []byte(`<28>Dec  2 16:49:23 host app[23410]: Test`)
	p := NewParser(WithYear(Year{YYYY: 2019}), WithRFC3339())
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(3),
	//   Severity: (*uint8)(4),
	//   Priority: (*uint8)(28),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2019-12-02 16:49:23 +0000 UTC),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)((len=5) "23410"),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_stampmilli() {
	i := []byte(`<28>Dec  2 16:49:23.123 host app[23410]: Test`)
	p := NewParser(WithYear(Year{YYYY: 2025}), WithSecondFractions())
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(3),
	//   Severity: (*uint8)(4),
	//   Priority: (*uint8)(28),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2025-12-02 16:49:23.123 +0000 UTC),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)((len=5) "23410"),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_stampmicro() {
	i := []byte(`<28>Dec  2 16:49:23.654321 host app[23410]: Test`)
	p := NewParser(WithYear(Year{YYYY: 2025}), WithSecondFractions())
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(3),
	//   Severity: (*uint8)(4),
	//   Priority: (*uint8)(28),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2025-12-02 16:49:23.654321 +0000 UTC),
	//   Hostname: (*string)((len=4) "host"),
	//   Appname: (*string)((len=3) "app"),
	//   ProcID: (*string)((len=5) "23410"),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=4) "Test")
	//  }
	// })
}

func Example_ciscoIOS() {
	i := []byte(`<189>269614: myhostname: Apr 11 10:02:08: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet7/0/34, changed state to up`)
	p := NewParser(WithYear(Year{YYYY: 2025}), WithCiscoIOSComponents(ciscoios.All))
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(23),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(189),
	//   MessageCounter: (*uint32)(269614),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2025-04-11 10:02:08 +0000 UTC),
	//   Hostname: (*string)((len=10) "myhostname"),
	//   Appname: (*string)((len=19) "%LINEPROTO-5-UPDOWN"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=69) "Line protocol on Interface GigabitEthernet7/0/34, changed state to up")
	//  }
	// })
}

func ExampleParser_ciscoIOSLeadingColon() {
	i := []byte(`<189>: *Jan  8 19:46:03.295: %SYS-5-CONFIG_I: Configured from console`)
	p := NewParser(WithYear(Year{YYYY: 2025}), WithCiscoIOSComponents(ciscoios.All))
	m, _ := p.Parse(i)
	output(m)
	// Output:
	// (*rfc3164.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(23),
	//   Severity: (*uint8)(5),
	//   Priority: (*uint8)(189),
	//   MessageCounter: (*uint32)(0),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(2025-01-08 19:46:03.295 +0000 UTC),
	//   Hostname: (*string)(<nil>),
	//   Appname: (*string)((len=15) "%SYS-5-CONFIG_I"),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)((len=23) "Configured from console")
	//  }
	// })
}

// ExampleParser_ciscoIOSConfigMismatch demonstrates a parsing error
// due to a mismatch between the device configuration and the parser configuration.
//
// The error message "expecting a sequence number" actually means:
// "I see digits that look like a sequence number, but you haven't enabled sequence number parsing. You need to configure the parser to handle this".
func ExampleParser_ciscoIOSConfigMismatch() {
	// Device configured with both message counter and sequence number
	i := []byte(`<189>237: 000485: *Jan  8 19:46:03.295: %SYS-5-CONFIG_I: Configured from console`)

	// Parser configured for message counter only (WRONG: it doesn't match device)
	p := NewParser(
		WithYear(Year{YYYY: 2025}),
		WithCiscoIOSComponents(ciscoios.DisableSequenceNumber|ciscoios.DisableHostname),
	)

	_, err := p.Parse(i)
	fmt.Printf("Error: %v\n", err)
	// Output:
	// Error: expecting a sequence number (from 1 to max 255 digits) [col 10]
}
