package nontransparent

import (
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

func Example_withoutTrailerAtEnd() {
	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}
	// Notice the message ends without trailer but we catch it anyway
	r := strings.NewReader("<1>1 2003-10-11T22:14:15.003Z host.local - - - - mex")
	NewParser(syslog.WithListener(acc)).Parse(r)
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (syslog.Message) <nil>,
	//   Error: (*ragel.ReadingError)(unexpected EOF)
	//  }
	// }
}

func Example_withCurrentYear_RFC3164() {
	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		if res != nil {
			// Force year to match the one in the comment below
			x, _ := res.Message.(*rfc3164.SyslogMessage)
			x.Timestamp = func(t1 *time.Time) *time.Time {
				currentY := time.Now().Year()
				t2 := t1.AddDate(2021-currentY, 0, 0)

				return &t2
			}(x.Timestamp)
			newRes := syslog.Result{Message: x, Error: res.Error}
			results = append(results, newRes)
		}
	}
	// Notice the message ends without trailer but we catch it anyway
	r := strings.NewReader("<13>Dec  2 16:31:03 host app: Test\n")
	NewParserRFC3164(
		syslog.WithListener(acc),
		syslog.WithMachineOptions(rfc3164.WithYear(rfc3164.CurrentYear{})),
	).Parse(r)
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (*rfc3164.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(1),
	//     Severity: (*uint8)(5),
	//     Priority: (*uint8)(13),
	//     Timestamp: (*time.Time)(2021-12-02 16:31:03 +0000 UTC),
	//     Hostname: (*string)((len=4) "host"),
	//     Appname: (*string)((len=3) "app"),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=4) "Test")
	//    }
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

func Example_bestEffortWithoutTrailerAtEnd() {
	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}
	// Notice the message ends without trailer but we catch it anyway
	r := strings.NewReader("<1>1 2003-10-11T22:14:15.003Z host.local - - - - mex")
	NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(acc)).Parse(r)
	output(results)
	// Output:
	// ([]syslog.Result) (len=1) {
	//  (syslog.Result) {
	//   Message: (*rfc5424.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(0),
	//     Severity: (*uint8)(1),
	//     Priority: (*uint8)(1),
	//     Timestamp: (*time.Time)(2003-10-11 22:14:15.003 +0000 UTC),
	//     Hostname: (*string)((len=10) "host.local"),
	//     Appname: (*string)(<nil>),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=3) "mex")
	//    },
	//    Version: (uint16) 1,
	//    StructuredData: (*map[string]map[string]string)(<nil>)
	//   }),
	//   Error: (error) <nil>
	//  }
	// }
}

func Example_bestEffortOnLastOne() {
	results := []syslog.Result{}
	acc := func(res *syslog.Result) {
		results = append(results, *res)
	}
	r := strings.NewReader("<1>1 - - - - - - -\n<3>1\n")
	NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()), syslog.WithListener(acc)).Parse(r)
	output(results)
	// Output:
	// ([]syslog.Result) (len=2) {
	//  (syslog.Result) {
	//   Message: (*rfc5424.SyslogMessage)({
	//    Base: (syslog.Base) {
	//     Facility: (*uint8)(0),
	//     Severity: (*uint8)(1),
	//     Priority: (*uint8)(1),
	//     Timestamp: (*time.Time)(<nil>),
	//     Hostname: (*string)(<nil>),
	//     Appname: (*string)(<nil>),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)((len=1) "-")
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
	//     Timestamp: (*time.Time)(<nil>),
	//     Hostname: (*string)(<nil>),
	//     Appname: (*string)(<nil>),
	//     ProcID: (*string)(<nil>),
	//     MsgID: (*string)(<nil>),
	//     Message: (*string)(<nil>)
	//    },
	//    Version: (uint16) 1,
	//    StructuredData: (*map[string]map[string]string)(<nil>)
	//   }),
	//   Error: (*errors.errorString)(parsing error [col 4])
	//  }
	// }
}

func Example_intoChannelWithLF() {
	messages := []string{
		"<2>1 - - - - - - A\nB",
		"<1>1 -",
		"<1>1 - - - - - - A\nB\nC\nD",
	}

	r, w := io.Pipe()

	go func() {
		defer w.Close()

		for _, m := range messages {
			// Write message (containing trailers to be interpreted as part of the syslog MESSAGE)
			w.Write([]byte(m))
			// Write non-transparent frame boundary
			w.Write([]byte{10})
			// Wait a random amount of time
			time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
		}
	}()

	results := make(chan *syslog.Result)
	ln := func(x *syslog.Result) {
		// Emit the result
		results <- x
	}

	p := NewParser(syslog.WithListener(ln), syslog.WithMachineOptions(rfc5424.WithBestEffort()))
	go func() {
		defer close(results)
		defer r.Close()
		p.Parse(r)
	}()

	// Consume results
	for r := range results {
		output(r)
	}

	// Output:
	// (*syslog.Result)({
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(2),
	//    Priority: (*uint8)(2),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=3) "A\nB")
	//   },
	//   Version: (uint16) 1,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (error) <nil>
	// })
	// (*syslog.Result)({
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(1),
	//    Priority: (*uint8)(1),
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
	//  Error: (*errors.errorString)(parsing error [col 6])
	// })
	// (*syslog.Result)({
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(1),
	//    Priority: (*uint8)(1),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=7) "A\nB\nC\nD")
	//   },
	//   Version: (uint16) 1,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (error) <nil>
	// })

}

func Example_intoChannelWithNUL() {
	messages := []string{
		"<2>1 - - - - - - A\x00B",
		"<1>1 -",
		"<1>1 - - - - - - A\x00B\x00C\x00D",
	}

	r, w := io.Pipe()

	go func() {
		defer w.Close()

		for _, m := range messages {
			// Write message (containing trailers to be interpreted as part of the syslog MESSAGE)
			w.Write([]byte(m))
			// Write non-transparent frame boundary
			w.Write([]byte{0})
			// Wait a random amount of time
			time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
		}
	}()

	results := make(chan *syslog.Result)
	ln := func(x *syslog.Result) {
		// Emit the result
		results <- x
	}

	p := NewParser(syslog.WithListener(ln), WithTrailer(NUL))

	go func() {
		defer close(results)
		defer r.Close()
		p.Parse(r)
	}()

	// Range over the results channel
	for r := range results {
		output(r)
	}

	// Output:
	// (*syslog.Result)({
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(2),
	//    Priority: (*uint8)(2),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=3) "A\x00B")
	//   },
	//   Version: (uint16) 1,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (error) <nil>
	// })
	// (*syslog.Result)({
	//  Message: (syslog.Message) <nil>,
	//  Error: (*errors.errorString)(parsing error [col 6])
	// })
	// (*syslog.Result)({
	//  Message: (*rfc5424.SyslogMessage)({
	//   Base: (syslog.Base) {
	//    Facility: (*uint8)(0),
	//    Severity: (*uint8)(1),
	//    Priority: (*uint8)(1),
	//    Timestamp: (*time.Time)(<nil>),
	//    Hostname: (*string)(<nil>),
	//    Appname: (*string)(<nil>),
	//    ProcID: (*string)(<nil>),
	//    MsgID: (*string)(<nil>),
	//    Message: (*string)((len=7) "A\x00B\x00C\x00D")
	//   },
	//   Version: (uint16) 1,
	//   StructuredData: (*map[string]map[string]string)(<nil>)
	//  }),
	//  Error: (error) <nil>
	// })
}

func output(out interface{}) {
	spew.Config.DisableCapacities = true
	spew.Config.DisablePointerAddresses = true
	spew.Dump(out)
}
