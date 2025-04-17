package octetcounting

import (
	"io"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

func output(out interface{}) {
	spew.Config.DisableCapacities = true
	spew.Config.DisablePointerAddresses = true
	spew.Dump(out)
}

func Example() {
	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}
	r := strings.NewReader("48 <1>1 2003-10-11T22:14:15.003Z host.local - - - -25 <3>1 - host.local - - - -38 <2>1 - host.local su - - - κόσμε")
	NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(acc)).Parse(r)
	output(results)
	// Output:
	// ([]syslog.Result) (len=3) {
	//  (syslog.Result) {
	//   Message: (*rfc5424.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(0),
	//     Severity: (*uint8)(1),
	//     Priority: (*uint8)(1),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(2003-10-11 22:14:15.003 +0000 UTC),
	//     Hostname: (*string)((len=10) "host.local"),
	//     Appname: (*string)(<nil>),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)(<nil>)
	//    },
	//    Version: (uint16) 1,
	//    StructuredData: (*map[string]map[string]string)(<nil>)
	//   }),
	//   Error: (error) <nil>
	//  },
	//  (syslog.Result) {
	//   Message: (*rfc5424.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(0),
	//     Severity: (*uint8)(3),
	//     Priority: (*uint8)(3),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(<nil>),
	//     Hostname: (*string)((len=10) "host.local"),
	//     Appname: (*string)(<nil>),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)(<nil>)
	//    },
	//    Version: (uint16) 1,
	//    StructuredData: (*map[string]map[string]string)(<nil>)
	//   }),
	//   Error: (error) <nil>
	//  },
	//  (syslog.Result) {
	//   Message: (*rfc5424.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(0),
	//     Severity: (*uint8)(2),
	//     Priority: (*uint8)(2),
	//     MessageCounter: (*uint32)(<nil>),
	//     Sequence: (*uint32)(<nil>),
	//     Timestamp: (*time.Time)(<nil>),
	//     Hostname: (*string)((len=10) "host.local"),
	//     Appname: (*string)((len=2) "su"),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=11) "κόσμε")
	//    },
	//    Version: (uint16) 1,
	//    StructuredData: (*map[string]map[string]string)(<nil>)
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

func Example_channel() {
	messages := []string{
		"16 <1>1 - - - - - -",
		"17 <2>12 A B C D E -",
		"16 <1>1",
	}

	r, w := io.Pipe()

	go func() {
		defer w.Close()

		for _, m := range messages {
			w.Write([]byte(m))
			time.Sleep(time.Millisecond * 220)
		}
	}()

	c := make(chan syslog.Result)
	emit := func(res *syslog.Result) {
		c <- *res
	}

	parser := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(emit))
	go func() {
		defer close(c)
		parser.Parse(r)
	}()

	for r := range c {
		output(r)
	}

	r.Close()

	// Output:
	// (syslog.Result) {
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(1),
	//    Priority: (*uint8)(1),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)(<nil>)
	//   },
	//   Version: (uint16) 1,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (error) <nil>
	// }
	// (syslog.Result) {
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(2),
	//    Priority: (*uint8)(2),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)(<nil>)
	//   },
	//   Version: (uint16) 12,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (*errors.errorString)(expecting a RFC3339MICRO timestamp or a nil value [col 6])
	// }
	// (syslog.Result) {
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(1),
	//    Priority: (*uint8)(1),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)(<nil>)
	//   },
	//   Version: (uint16) 1,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (*errors.errorString)(parsing error [col 4])
	// }
}

func Example_channelOpenBSD() {
	messages := []string{
		"42 <46>Apr 28 11:53:44 syslogd[18823]: start\n",
		"44 <47>Apr 28 11:53:44 syslogd[18823]: running\n",
		"88 <86>Apr 28 11:53:46 doas: catap ran command ls / as root from /home/catap/src/go-syslog\n",
	}

	r, w := io.Pipe()

	go func() {
		defer w.Close()

		for _, m := range messages {
			w.Write([]byte(m))
			time.Sleep(time.Millisecond * 220)
		}
	}()

	c := make(chan syslog.Result)
	emit := func(res *syslog.Result) {
		c <- *res
	}

	parser := NewParserRFC3164(syslog.WithMachineOptions(rfc3164.WithBestEffort()), syslog.WithListener(emit))
	go func() {
		defer close(c)
		parser.Parse(r)
	}()

	for r := range c {
		output(r)
	}

	r.Close()

	// Output:
	// (syslog.Result) {
	//  Message: (*rfc3164.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(5),
	//    Severity: (*uint8)(6),
	//    Priority: (*uint8)(46),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(0000-04-28 11:53:44 +0000 UTC),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)((len=7) "syslogd"),
	//    ProcID: (*string)((len=5) "18823"),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=5) "start")
	//   }
	//  }),
	//  Error: (error) <nil>
	// }
	// (syslog.Result) {
	//  Message: (*rfc3164.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(5),
	//    Severity: (*uint8)(7),
	//    Priority: (*uint8)(47),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(0000-04-28 11:53:44 +0000 UTC),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)((len=7) "syslogd"),
	//    ProcID: (*string)((len=5) "18823"),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=7) "running")
	//   }
	//  }),
	//  Error: (error) <nil>
	// }
	// (syslog.Result) {
	//  Message: (*rfc3164.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(10),
	//    Severity: (*uint8)(6),
	//    Priority: (*uint8)(86),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(0000-04-28 11:53:46 +0000 UTC),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)((len=4) "doas"),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=61) "catap ran command ls / as root from /home/catap/src/go-syslog")
	//   }
	//  }),
	//  Error: (error) <nil>
	// }
}

func Example_channelOpenBSDWithCurrentYear() {
	messages := []string{
		"42 <46>Apr 28 11:53:44 syslogd[18823]: start\n",
		"44 <47>Apr 28 11:53:44 syslogd[18823]: running\n",
		"88 <86>Apr 28 11:53:46 doas: catap ran command ls / as root from /home/catap/src/go-syslog\n",
	}

	r, w := io.Pipe()

	go func() {
		defer w.Close()

		for _, m := range messages {
			w.Write([]byte(m))
			time.Sleep(time.Millisecond * 220)
		}
	}()

	c := make(chan syslog.Result)
	emit := func(res *syslog.Result) {
		c <- *res
	}

	parser := NewParserRFC3164(
		syslog.WithMachineOptions(rfc3164.WithBestEffort(), rfc3164.WithYear(rfc3164.CurrentYear{})),
		syslog.WithListener(emit),
	)
	go func() {
		defer close(c)
		parser.Parse(r)
	}()

	for r := range c {
		mes := r
		if r.Message != nil {
			// Force year to match the one in the comment below
			x := r.Message.(*rfc3164.SyslogMessage)
			x.Timestamp = func(t1 *time.Time) *time.Time {
				currentY := time.Now().Year()
				t2 := t1.AddDate(2024-currentY, 0, 0)

				return &t2
			}(x.Timestamp)
			mes = syslog.Result{Message: x, Error: r.Error}
		}
		output(mes)
	}

	r.Close()

	// Output:
	// (syslog.Result) {
	//  Message: (*rfc3164.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(5),
	//    Severity: (*uint8)(6),
	//    Priority: (*uint8)(46),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(2024-04-28 11:53:44 +0000 UTC),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)((len=7) "syslogd"),
	//    ProcID: (*string)((len=5) "18823"),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=5) "start")
	//   }
	//  }),
	//  Error: (error) <nil>
	// }
	// (syslog.Result) {
	//  Message: (*rfc3164.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(5),
	//    Severity: (*uint8)(7),
	//    Priority: (*uint8)(47),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(2024-04-28 11:53:44 +0000 UTC),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)((len=7) "syslogd"),
	//    ProcID: (*string)((len=5) "18823"),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=7) "running")
	//   }
	//  }),
	//  Error: (error) <nil>
	// }
	// (syslog.Result) {
	//  Message: (*rfc3164.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(10),
	//    Severity: (*uint8)(6),
	//    Priority: (*uint8)(86),
	//    MessageCounter: (*uint32)(<nil>),
	//    Sequence: (*uint32)(<nil>),
	//    Timestamp: (*time.Time)(2024-04-28 11:53:46 +0000 UTC),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)((len=4) "doas"),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=61) "catap ran command ls / as root from /home/catap/src/go-syslog")
	//   }
	//  }),
	//  Error: (error) <nil>
	// }
}
