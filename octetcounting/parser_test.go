package octetcounting

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/auto"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	syslogtesting "github.com/leodido/go-syslog/v4/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	descr             string
	input             string
	results           []syslog.Result
	bestEffortResults []syslog.Result
	maxMessageLength  int
}

var testCases []testCase

func getTimestampError(col int) error {
	return fmt.Errorf(rfc5424.ErrTimestamp+rfc5424.ColumnPositionTemplate, col)
}

func getParsingError(col int) error {
	return fmt.Errorf(rfc5424.ErrParse+rfc5424.ColumnPositionTemplate, col)
}

func getTestCases() []testCase {
	return []testCase{
		{
			descr: "empty",
			input: "",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", EOF, MSGLEN)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", EOF, MSGLEN)},
			},
		},
		{
			descr: "parsing error - contains non-numeric characters",
			input: "123abc <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("a")}, WS)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("a")}, WS)},
			},
		},
		{
			descr: "parsing error - uint64 overflow",
			input: "18446744073709551616 <1>1 - - - - - -", // 2^64, one more than max uint64
			results: []syslog.Result{
				{Error: errors.New(string(ErrMsgInvalidLength))},
			},
			bestEffortResults: []syslog.Result{
				{Error: errors.New(string(ErrMsgInvalidLength))},
			},
		},

		{
			descr: "format error - starts with letter",
			input: "abc <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("a")}, MSGLEN)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("a")}, MSGLEN)},
			},
		},
		{
			descr: "format error - starts with hyphen",
			input: "-10 <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("-")}, MSGLEN)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("-")}, MSGLEN)},
			},
		},
		{
			descr: "format error - starts with zero",
			input: "01 <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("0")}, MSGLEN)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("0")}, MSGLEN)},
			},
		},
		{
			descr: "invalid message length - negative",
			input: "-10 <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("-")}, MSGLEN)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("-")}, MSGLEN)},
			},
		},
		{
			descr: "invalid message length - leading zero",
			input: "01 <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("0")}, MSGLEN)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("0")}, MSGLEN)},
			},
		},
		{
			descr: "invalid message length - overflow uint64",
			input: "18446744073709551616 <1>1 - - - - - -", // 2^64, one more than max uint64
			results: []syslog.Result{
				{Error: errors.New(string(ErrMsgInvalidLength))},
			},
			bestEffortResults: []syslog.Result{
				{Error: errors.New(string(ErrMsgInvalidLength))},
			},
		},
		{
			descr: "1st ok/2nd mf", // mf means malformed syslog message
			input: "16 <1>1 - - - - - -17 <2>12 A B C D E -",
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Error: getTimestampError(6),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(2).SetVersion(12),
					Error:   getTimestampError(6),
				},
			},
		},
		{
			descr: "1st ok/2nd ko", // ko means wrong token
			input: "16 <1>1 - - - - - -xaaa",
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("x")}, MSGLEN),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("x")}, MSGLEN),
				},
			},
		},
		{
			descr: "1st ml/2nd ko",
			input: "16 <1>1 A B C D E -xaaa",
			// results w/o best effort
			results: []syslog.Result{
				{
					Error: getTimestampError(5),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
					Error:   getTimestampError(5),
				},
				{
					Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("x")}, MSGLEN),
				},
			},
		},
		{
			descr: "1st ok//utf8",
			input: "23 <1>1 - - - - - - hellø", // msglen MUST be the octet count
			//results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(1).
						SetVersion(1).
						SetMessage("hellø"),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(1).
						SetVersion(1).
						SetMessage("hellø"),
				},
			},
		},
		{
			descr: "1st ko//incomplete SYSLOGMSG",
			input: "16 <1>1",
			// results w/o best effort
			results: []syslog.Result{
				{
					Error: fmt.Errorf(`found %s after "%s", expecting a %s containing %d octets`, EOF, "<1>1", SYSLOGMSG, 16),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
					Error:   getParsingError(4),
					// Error:   fmt.Errorf(`found %s after "%s", expecting a %s containing %d octets`, EOF, "<1>1", SYSLOGMSG, 16),
				},
			},
		},
		{
			descr: "1st ko//missing WS found ILLEGAL",
			input: "16<1>1",
			// results w/o best effort
			results: []syslog.Result{
				{
					Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("<")}, WS),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Error: fmt.Errorf("found %s, expecting a %s", Token{ILLEGAL, []byte("<")}, WS),
				},
			},
		},
		{
			descr: "1st ko//missing WS found EOF",
			input: "1",
			// results w/o best effort
			results: []syslog.Result{
				{
					Error: fmt.Errorf("found %s, expecting a %s", EOF, WS),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Error: fmt.Errorf("found %s, expecting a %s", EOF, WS),
				},
			},
		},
		{
			descr: "1st ok/2nd ok/LF/3rd ok", // LF means new line aka \n
			input: "48 <1>1 2003-10-11T22:14:15.003Z host.local - - - -25 <3>1 - host.local - - - -\n38 <2>1 - host.local su - - - κόσμε",
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(1).
						SetVersion(1).
						SetTimestamp("2003-10-11T22:14:15.003Z").
						SetHostname("host.local"),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(3).
						SetVersion(1).
						SetHostname("host.local"),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(2).
						SetVersion(1).
						SetHostname("host.local").
						SetAppname("su").
						SetMessage("κόσμε"),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(1).
						SetVersion(1).
						SetTimestamp("2003-10-11T22:14:15.003Z").
						SetHostname("host.local"),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(3).
						SetVersion(1).
						SetHostname("host.local"),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(2).
						SetVersion(1).
						SetHostname("host.local").
						SetAppname("su").
						SetMessage("κόσμε"),
				},
			},
		},
		{
			descr: "1st ok/2nd mf/3rd ok", // mf means malformed syslog message
			input: "16 <1>1 - - - - - -17 <2>12 A B C D E -16 <1>1 - - - - - -",
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Error: getTimestampError(6),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(2).SetVersion(12),
					Error:   getTimestampError(6),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
			},
		},
		{
			descr: "1st ok//defaultmax",
			input: fmt.Sprintf(
				"%d <%d>%d %s %s %s %s %s - %s",
				DefaultMaxSize,
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.MaxMessage),
			),
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
			},
		},
		{
			descr: "1st ok//longer-max",
			input: fmt.Sprintf(
				"65529 <%d>%d %s %s %s %s %s - %s",
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.LongerMaxMessage),
			),
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.LongerMaxMessage)),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.LongerMaxMessage)),
				},
			},
			maxMessageLength: 65529,
		},
		{
			descr: "1st ok/2nd ok//max/max",
			input: fmt.Sprintf(
				"%d <%d>%d %s %s %s %s %s - %s%d <%d>%d %s %s %s %s %s - %s",
				DefaultMaxSize,
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.MaxMessage),
				DefaultMaxSize,
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.MaxMessage),
			),
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
			},
		},
		{
			descr: "1st ok/2nd ok//longer-max/longer-max",
			input: fmt.Sprintf(
				"65529 <%d>%d %s %s %s %s %s - %s65529 <%d>%d %s %s %s %s %s - %s",
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.LongerMaxMessage),
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.LongerMaxMessage),
			),
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.LongerMaxMessage)),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.LongerMaxMessage)),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.LongerMaxMessage)),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.LongerMaxMessage)),
				},
			},
			maxMessageLength: 65529,
		},
		{
			descr: "1st ok/2nd ok/3rd ok//max/no/max",
			input: fmt.Sprintf(
				"%d <%d>%d %s %s %s %s %s - %s16 <1>1 - - - - - -%d <%d>%d %s %s %s %s %s - %s",
				DefaultMaxSize,
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.MaxMessage),
				DefaultMaxSize,
				syslogtesting.MaxPriority,
				syslogtesting.MaxVersion,
				syslogtesting.MaxRFC3339MicroTimestamp,
				string(syslogtesting.MaxHostname),
				string(syslogtesting.MaxAppname),
				string(syslogtesting.MaxProcID),
				string(syslogtesting.MaxMsgID),
				string(syslogtesting.MaxMessage),
			),
			// results w/o best effort
			results: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
				},
				{
					Message: (&rfc5424.SyslogMessage{}).
						SetPriority(syslogtesting.MaxPriority).
						SetVersion(syslogtesting.MaxVersion).
						SetTimestamp(syslogtesting.MaxRFC3339MicroTimestamp).
						SetHostname(string(syslogtesting.MaxHostname)).
						SetAppname(string(syslogtesting.MaxAppname)).
						SetProcID(string(syslogtesting.MaxProcID)).
						SetMsgID(string(syslogtesting.MaxMsgID)).
						SetMessage(string(syslogtesting.MaxMessage)),
				},
			},
		},
		{
			descr: "MSGLEN gt max message length",
			input: "16 <1>1 - - - - - -",
			results: []syslog.Result{
				{Error: fmt.Errorf(string(ErrMsgTooLarge), 16, 10)},
			},
			bestEffortResults: []syslog.Result{
				{Error: fmt.Errorf(string(ErrMsgTooLarge), 16, 10)},
			},
			maxMessageLength: 10,
		},
		{
			descr: "1st uf/2nd ok//incomplete SYSLOGMSG/notdetectable",
			input: "16 <1>217 <11>1 - - - - - -",
			// results w/o best effort
			results: []syslog.Result{
				{
					Error: getTimestampError(7),
				},
			},
			// results with best effort
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(217),
					Error:   getTimestampError(7),
				},
				{
					Error: fmt.Errorf("found %s, expecting a %s", WS, MSGLEN),
				},
			},
		},
	}
}

func getSystemLimitTestCases() []testCase {
	nearMaxInt := uint64(MaxInt) - 1000
	exactMaxInt := uint64(MaxInt)

	return []testCase{
		{
			descr: "system limit - near MaxInt but valid",
			input: fmt.Sprintf("%d <1>1 - - - - - -", nearMaxInt),
			results: []syslog.Result{
				{Error: fmt.Errorf(`found %s after "%s", expecting a %s containing %d octets`, EOF, "<1>1 - - - - - -", SYSLOGMSG, nearMaxInt)},
			},
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
					Error:   fmt.Errorf(`found %s after "%s", expecting a %s containing %d octets`, EOF, "<1>1 - - - - - -", SYSLOGMSG, nearMaxInt),
				},
			},
			maxMessageLength: MaxInt,
		},
		{
			descr: "system limit - exactly at MaxInt",
			input: fmt.Sprintf("%d <1>1 - - - - - -", exactMaxInt),
			results: []syslog.Result{
				{Error: fmt.Errorf(`found %s after "%s", expecting a %s containing %d octets`, EOF, "<1>1 - - - - - -", SYSLOGMSG, exactMaxInt)},
			},
			bestEffortResults: []syslog.Result{
				{
					Message: (&rfc5424.SyslogMessage{}).SetPriority(1).SetVersion(1),
					Error:   fmt.Errorf(`found %s after "%s", expecting a %s containing %d octets`, EOF, "<1>1 - - - - - -", SYSLOGMSG, exactMaxInt),
				},
			},
			maxMessageLength: MaxInt,
		},
	}
}

func init() {
	testCases = append(getTestCases(), getSystemLimitTestCases()...)
}

func TestParse(t *testing.T) {
	for i := range testCases {
		tc := testCases[i] // tests could be running in parallel, needs to be scoped.
		if tc.maxMessageLength == 0 {
			tc.maxMessageLength = DefaultMaxSize
		}
		t.Run(fmt.Sprintf("strict/%s", tc.descr), func(t *testing.T) {
			t.Parallel()

			res := []syslog.Result{}
			strictParser := NewParser(
				syslog.WithListener(func(r *syslog.Result) {
					res = append(res, *r)
				}),
				syslog.WithMaxMessageLength(tc.maxMessageLength))
			strictParser.Parse(strings.NewReader(tc.input))

			assert.Equal(t, tc.results, res)
		})
		t.Run(fmt.Sprintf("effort/%s", tc.descr), func(t *testing.T) {
			t.Parallel()

			res := []syslog.Result{}
			effortParser := NewParser(
				syslog.WithMachineOptions(rfc5424.WithBestEffort()),
				syslog.WithListener(func(r *syslog.Result) {
					res = append(res, *r)
				}),
				syslog.WithMaxMessageLength(tc.maxMessageLength),
			)
			effortParser.Parse(strings.NewReader(tc.input))

			assert.Equal(t, tc.bestEffortResults, res)
		})
	}
}

func TestParserBestEffortCompatibility(t *testing.T) {
	// Test original API works
	p1 := NewParser()
	assert.False(t, p1.HasBestEffort())

	p2 := NewParser(syslog.WithBestEffort())
	assert.True(t, p2.HasBestEffort())

	// Test new API works too
	p3 := NewParser(syslog.WithMachineOptions(rfc5424.WithBestEffort()))
	assert.True(t, p3.HasBestEffort())
}

// --- Auto-detect parser tests ---

func TestParseAuto_MixedStream(t *testing.T) {
	rfc5424Msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`
	rfc3164Msg := `<13>Dec  2 16:31:03 host app: Test`
	stream := fmt.Sprintf("%d %s%d %s", len(rfc5424Msg), rfc5424Msg, len(rfc3164Msg), rfc3164Msg)

	var results []*syslog.Result
	p := NewParserAuto(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))

	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 2)
	require.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
	require.NoError(t, results[1].Error)
	assert.Equal(t, auto.FormatRFC3164, auto.DetectFormat(results[1].Message))
}

func TestParseAuto_RFC5424Only(t *testing.T) {
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] msg`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_RFC3164Only(t *testing.T) {
	msg := `<13>Dec  2 16:31:03 host app: Test`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(syslog.WithListener(func(r *syslog.Result) {
		results = append(results, r)
	}))
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC3164, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_WithRFC3164MachineOptions(t *testing.T) {
	msg := `<13>Dec  2 16:31:03 host app: Test`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		auto.WithRFC3164MachineOptions(rfc3164.WithYear(rfc3164.Year{YYYY: 2025})),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	sm := results[0].Message.(*rfc3164.SyslogMessage)
	require.NotNil(t, sm.Timestamp)
	assert.Equal(t, 2025, sm.Timestamp.Year())
}

func TestParseAuto_WithRFC5424MachineOptions(t *testing.T) {
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] msg`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		auto.WithRFC5424MachineOptions(rfc5424.WithCompliantMsg()),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC5424, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_WithoutFallback(t *testing.T) {
	msg := `<13>Dec  2 16:31:03 host app: Test`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		auto.WithoutParserFallback(),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.Equal(t, auto.FormatRFC3164, auto.DetectFormat(results[0].Message))
}

func TestParseAuto_BestEffort(t *testing.T) {
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		syslog.WithBestEffort(),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Message)
	assert.Error(t, results[0].Error)
}

func TestParseAuto_WithMachineOptions(t *testing.T) {
	// syslog.WithMachineOptions should forward to both inner parsers.
	// Use rfc5424.WithBestEffort() as a generic machine option.
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		syslog.WithMachineOptions(rfc5424.WithBestEffort()),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	// Best-effort should return partial message for truncated 5424.
	assert.NotNil(t, results[0].Message)
	assert.Error(t, results[0].Error)
}

func TestParseAuto_WithMachineOptions_FormatSpecific(t *testing.T) {
	// Format-specific options via syslog.WithMachineOptions must not panic
	// when forwarded to the wrong inner machine type.
	msg := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] msg`
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	assert.NotPanics(t, func() {
		p := NewParserAuto(
			syslog.WithListener(func(r *syslog.Result) {
				results = append(results, r)
			}),
			syslog.WithMachineOptions(rfc5424.WithCompliantMsg()),
		)
		p.Parse(strings.NewReader(stream))
	})

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Message)
	assert.NoError(t, results[0].Error)
}

func TestParseAuto_RFC3164_EmbeddedNewline(t *testing.T) {
	// Regression test for issue #15: embedded newlines in RFC 3164 messages
	// must be preserved when using octet-counted framing.
	msg := "<13>Dec  2 16:31:03 host app: line1\nline2"
	stream := fmt.Sprintf("%d %s", len(msg), msg)

	var results []*syslog.Result
	p := NewParserAuto(
		syslog.WithListener(func(r *syslog.Result) {
			results = append(results, r)
		}),
		syslog.WithBestEffort(),
	)
	p.Parse(strings.NewReader(stream))

	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	sm := results[0].Message.(*rfc3164.SyslogMessage)
	require.NotNil(t, sm.Message)
	assert.Contains(t, *sm.Message, "line1\nline2")
}
