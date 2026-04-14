package rfc3195_test

import (
	"fmt"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3195"
)

func init() {
	spew.Config.DisableCapacities = true
	spew.Config.DisablePointerAddresses = true
}

func output(out interface{}) {
	spew.Dump(out)
}

// beepFrame builds a raw BEEP data frame string for use in examples.
func beepFrame(keyword string, channel, msgno int, more byte, seqno int, ansno int, payload string) string {
	size := len(payload)
	header := fmt.Sprintf("%s %d %d %c %d %d", keyword, channel, msgno, more, seqno, size)
	if keyword == "ANS" {
		header += " " + fmt.Sprintf("%d", ansno)
	}
	return header + "\r\n" + payload + "END\r\n"
}

// Example_raw demonstrates parsing RFC 3195 RAW profile frames containing
// RFC 5424 syslog messages. Each ANS frame carries one syslog message
// terminated by CRLF. A NUL frame signals end of exchange.
func Example_raw() {
	payload := "<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut=\"3\"] An application event log entry...\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	var results []syslog.Result
	p := rfc3195.NewParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, *r)
	}))
	p.Parse(strings.NewReader(input))
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (*rfc5424.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(20),
	//     Severity: (*uint8)(5),
	//     Priority: (*uint8)(165),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(2018-10-11 22:14:15.003 +0000 UTC),
	//     Hostname: (*string)((len=9) "mymach.it"),
	//     Appname: (*string)((len=1) "e"),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)((len=1) "1"),
	//     Message: (*string)((len=33) "An application event log entry...")
	//    },
	//    Version: (uint16) 4,
	//    StructuredData: (*map[string]map[string]string)((len=1) {
	//     (string) (len=8) "ex@32473": (map[string]string) (len=1) {
	//      (string) (len=3) "iut": (string) (len=1) "3"
	//     }
	//    })
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

// Example_rawRFC3164 demonstrates parsing RFC 3195 RAW profile frames
// containing RFC 3164 (BSD syslog) messages.
func Example_rawRFC3164() {
	payload := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	var results []syslog.Result
	p := rfc3195.NewParserRFC3164(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, *r)
	}))
	p.Parse(strings.NewReader(input))
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (*rfc3164.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(4),
	//     Severity: (*uint8)(2),
	//     Priority: (*uint8)(34),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(0000-10-11 22:14:15 +0000 UTC),
	//     Hostname: (*string)((len=9) "mymachine"),
	//     Appname: (*string)((len=2) "su"),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=16) "'su root' failed")
	//    }
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

// Example_cooked demonstrates parsing RFC 3195 COOKED profile frames.
// The COOKED profile carries syslog data as XML <entry> elements with
// attributes for facility, severity, timestamp, tag, and device identity.
func Example_cooked() {
	xmlPayload := `<entry facility='4' severity='2' timestamp='Oct 11 22:14:15' tag='su' deviceFQDN='mymachine.example.com'>'su root' failed for lonvick on /dev/pts/8</entry>`
	input := beepFrame("ANS", 1, 0, '.', 0, 0, xmlPayload) +
		beepFrame("NUL", 1, 0, '.', len(xmlPayload), -1, "")

	var results []syslog.Result
	p := rfc3195.NewCookedParser(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, *r)
	}))
	p.Parse(strings.NewReader(input))
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (*rfc3195.CookedMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(4),
	//     Severity: (*uint8)(2),
	//     Priority: (*uint8)(34),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(0000-10-11 22:14:15 +0000 UTC),
	//     Hostname: (*string)((len=21) "mymachine.example.com"),
	//     Appname: (*string)((len=2) "su"),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=42) "'su root' failed for lonvick on /dev/pts/8")
	//    },
	//    DeviceFQDN: (*string)((len=21) "mymachine.example.com"),
	//    DeviceIP: (*string)(<nil>),
	//    PathID: (*string)(<nil>)
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

// Example_cookedWithOptions demonstrates the COOKED profile with year and
// timezone options. RFC 3164 timestamps lack a year; WithCookedYear sets it.
// WithCookedTimezone interprets timestamps in the given location.
func Example_cookedWithOptions() {
	est, _ := time.LoadLocation("EST")
	xmlPayload := `<entry facility='4' severity='2' timestamp='Oct 11 22:14:15' tag='su' deviceFQDN='mymachine.example.com'>'su root' failed</entry>`
	input := beepFrame("ANS", 1, 0, '.', 0, 0, xmlPayload) +
		beepFrame("NUL", 1, 0, '.', len(xmlPayload), -1, "")

	var results []syslog.Result
	p := rfc3195.NewCookedParser(
		rfc3195.WithCookedYear(2025),
		rfc3195.WithCookedTimezone(est),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, *r)
		}),
	)
	p.Parse(strings.NewReader(input))
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (*rfc3195.CookedMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(4),
	//     Severity: (*uint8)(2),
	//     Priority: (*uint8)(34),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(2025-10-11 22:14:15 -0500 EST),
	//     Hostname: (*string)((len=21) "mymachine.example.com"),
	//     Appname: (*string)((len=2) "su"),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=16) "'su root' failed")
	//    },
	//    DeviceFQDN: (*string)((len=21) "mymachine.example.com"),
	//    DeviceIP: (*string)(<nil>),
	//    PathID: (*string)(<nil>)
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

// Example_rawBestEffort demonstrates best-effort parsing in the RAW profile.
// When the syslog message is malformed, best-effort mode returns whatever
// was successfully parsed along with the error.
func Example_rawBestEffort() {
	payload := "<1>1 A - - - - - -\r\n"
	input := beepFrame("ANS", 1, 0, '.', 0, 0, payload) +
		beepFrame("NUL", 1, 0, '.', len(payload), -1, "")

	var results []syslog.Result
	p := rfc3195.NewParser(
		syslog.WithBestEffort(),
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, *r)
		}),
	)
	p.Parse(strings.NewReader(input))
	output(results[0].Message)
	fmt.Println(results[0].Error)
	// Output:
	// (*rfc5424.SyslogMessage)({
	//  Base: (syslog.Base) {
	//   Facility: (*uint8)(0),
	//   Severity: (*uint8)(1),
	//   Priority: (*uint8)(1),
	//   MessageCounter: (*uint32)(<nil>),
	//   Sequence: (*uint32)(<nil>),
	//   Timestamp: (*time.Time)(<nil>),
	//   Hostname: (*string)(<nil>),
	//   Appname: (*string)(<nil>),
	//   ProcID: (*string)(<nil>),
	//   MsgID: (*string)(<nil>),
	//   Message: (*string)(<nil>)
	//  },
	//  Version: (uint16) 1,
	//  StructuredData: (*map[string]map[string]string)(<nil>)
	// })
	// expecting a RFC3339MICRO timestamp or a nil value [col 5]
}
