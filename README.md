[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)

**A parser for Syslog messages and transports**.

> [Blazing fast](#Performances) Syslog parsers

_By [@leodido](https://github.com/leodido)_.

_This is the official continuation of influxdata/go-syslog_.

This module includes:

- an [RFC5424-compliant parser and builder](/rfc5424)
- an [RFC3164-compliant parser](/rfc3164) - ie., BSD-syslog messages
- an [auto-detect parser](/auto) that determines RFC 3164 vs RFC 5424 format per-message
- an [RFC3195 parser](/rfc3195) for syslog over [BEEP](https://datatracker.ietf.org/doc/html/rfc3195) (RAW and COOKED profiles)
- a parser that works on streams for syslog with [octet counting](https://datatracker.ietf.org/doc/html/rfc6587#section-3.4.1) framing technique, see [octetcounting](/octetcounting)
- a parser that works on streams for syslog with [non-transparent](https://tools.ietf.org/html/rfc6587#section-3.4.2) framing technique, see [nontransparent](/nontransparent)

It can parse syslog messages received over:

- TLS with octet count ([RFC5425](https://tools.ietf.org/html/rfc5425))
- TCP with non-transparent framing or with octet count ([RFC 6587](https://tools.ietf.org/html/rfc6587))
- UDP carrying one message per packet ([RFC5426](https://tools.ietf.org/html/rfc5426))

## Installation

Requires **Go 1.22** or later.

```
go get github.com/leodido/go-syslog/v4
```

## Docs

[![Documentation](https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge)](https://pkg.go.dev/github.com/leodido/go-syslog/v4)

The [docs](docs/) directory contains `.dot` files representing the finite-state machines (FSMs) implementing the syslog parsers and transports.

## Usage

[![Build with Ona](https://ona.com/build-with-ona.svg)](https://app.ona.com/#https://github.com/leodido/go-syslog)

Parse RFC5424 messages with `rfc5424.NewParser`. The RFC3164 parser uses the
same interface; its options are demonstrated in
[rfc3164/example_test.go](./rfc3164/example_test.go).

```go
i := []byte(`<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`)
p := rfc5424.NewParser()
m, e := p.Parse(i)
```

This results in `m` being equal to:

```go
// (*rfc5424.SyslogMessage)({
//  Base: (syslog.Base) {
//   Facility: (*uint8)(20),
//   Severity: (*uint8)(5),
//   Priority: (*uint8)(165),
//   Timestamp: (*time.Time)(2018-10-11 22:14:15.003 +0000 UTC),
//   Hostname: (*string)((len=9) "mymach.it"),
//   Appname: (*string)((len=1) "e"),
//   ProcID: (*string)(<nil>),
//   MsgID: (*string)((len=1) "1"),
//   Message: (*string)((len=33) "An application event log entry...")
//  },
//  Version: (uint16) 4,
//  StructuredData: (*map[string]map[string]string)((len=1) {
//   (string) (len=8) "ex@32473": (map[string]string) (len=1) {
//    (string) (len=3) "iut": (string) (len=1) "3"
//   }
//  })
// })
```

`e` is nil because the input is a valid RFC5424 message.

### Messages without PRI

Both parsers require PRI by default. Use `WithOptionalPriority()` to accept an
otherwise valid message without it:

```go
rfc3164Parser := rfc3164.NewParser(rfc3164.WithOptionalPriority())
rfc5424Parser := rfc5424.NewParser(rfc5424.WithOptionalPriority())
```

When PRI is absent, `Priority`, `Facility`, and `Severity` are nil. Options can
be combined; for example, VMware ESXi messages commonly need both optional PRI
and fractional RFC3339 timestamps:

```go
esxiParser := rfc3164.NewParser(
    rfc3164.WithOptionalPriority(),
    rfc3164.WithRFC3339(),
)
```

### Best effort mode

With `WithBestEffort()`, a parse error returns the fields collected before the
failure. An RFC5424 partial result requires PRI and VERSION, or VERSION alone
when `WithOptionalPriority()` is also set.

```go
i := []byte("<1>1 A - - - - - -")
p := rfc5424.NewParser(rfc5424.WithBestEffort())
m, e := p.Parse(i)
```

```go
// (*rfc5424.SyslogMessage)({
//  Base: (syslog.Base) {
//   Facility: (*uint8)(0),
//   Severity: (*uint8)(1),
//   Priority: (*uint8)(1),
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
```

```go
// expecting a RFC3339MICRO timestamp or a nil value [col 5]
```

Both `m` and `e` are non-nil because the parser collected a valid partial
RFC5424 message before the error.

### Builder

Use `SyslogMessage` to construct RFC5424 messages. `Valid()` checks parser-level
structure; `String()` requires PRI. Setters ignore values that do not match the
grammar.

```go
msg := &rfc5424.SyslogMessage{}
msg.SetTimestamp("not a RFC3339MICRO timestamp")
msg.Valid() // Not yet a valid message (try msg.Valid())
msg.SetPriority(191)
msg.SetVersion(1)
msg.Valid() // Now it is minimally valid
```

The invalid timestamp is ignored, so `Timestamp` remains nil.

```go
// (*rfc5424.SyslogMessage)({
//  Base: (syslog.Base) {
//   Facility: (*uint8)(23),
//   Severity: (*uint8)(7),
//   Priority: (*uint8)(191),
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
```

```go
str, _ := msg.String()
// <191>1 - - - - - -
```

### Auto-detect

Use the [auto](/auto) package when a source mixes RFC5424 and RFC3164 messages.

```go
m := auto.NewMachine()
msg, err := m.Parse(input)
fmt.Println(auto.DetectFormat(msg)) // "rfc5424" or "rfc3164"
```

Pass format-specific options to each inner parser:

```go
m := auto.NewMachine(
    auto.WithRFC3164Options(rfc3164.WithYear(rfc3164.Year{YYYY: 2025})),
    auto.WithRFC5424Options(rfc5424.WithCompliantMsg()),
)
```

Priorityless auto-detection requires the option on both inner parsers:

```go
m := auto.NewMachine(
    auto.WithRFC3164Options(rfc3164.WithOptionalPriority()),
    auto.WithRFC5424Options(rfc5424.WithOptionalPriority()),
)
```

The stream packages also expose `NewParserAuto` - see
[octet counting](#octet-counting) and [non-transparent](#non-transparent)
below. Their auto-detect parsers currently require each syslog payload to begin
with PRI. Priorityless auto-detection is available only through `auto.Machine`.

For messages without PRI, auto-detection recognizes RFC3164 timestamps that
start with a three-letter month or a four-digit year followed by `-`. Other
priorityless inputs are tried as RFC5424 first. Unless `WithoutFallback()` is
set, a complete parse failure causes the other parser to be tried.

## Message transfer

Excluding encapsulating one message for packet in packet protocols there are two ways to transfer syslog messages over streams.

The older - ie., the **non-transparent** framing - and the newer one - ie., the **octet counting** framing - which is reliable and has not been seen to cause problems noted with the non-transparent one.

This library provide stream parsers for both.

### Octet counting

In short, [RFC5425](https://tools.ietf.org/html/rfc5425#section-4.3) and [RFC6587](https://tools.ietf.org/html/rfc6587), aside from the protocol considerations, describe a **transparent framing** technique for Syslog messages that uses the **octect counting** technique - ie., the message length of the incoming message.

Each Syslog message is sent with a prefix representing the number of bytes it is made of.

The [octecounting package](./octetcounting) parses messages stream following such rule.

To quickly understand how to use it please have a look at the [example file](./octetcounting/example_test.go).

If you have mixed RFC 5424 and RFC 3164 messages in the same stream, use `NewParserAuto`:

```go
p := octetcounting.NewParserAuto(
    syslog.WithListener(func(r *syslog.Result) {
        fmt.Println(auto.DetectFormat(r.Message))
    }),
    syslog.WithBestEffort(),
)
p.Parse(reader)
```

### Non transparent

The [RFC6587](https://tools.ietf.org/html/rfc6587#section-3.4.2) also describes the **non-transparent framing** transport of syslog messages.

In such case the messages are separated by a trailer, usually a line feed.

The [nontransparent package](./nontransparent) parses message stream following such [technique](https://tools.ietf.org/html/rfc6587#section-3.4.2).

To quickly understand how to use it please have a look at the [example file](./nontransparent/example_test.go).

Same as octet counting, use `NewParserAuto` for mixed-format streams:

```go
p := nontransparent.NewParserAuto(
    syslog.WithListener(func(r *syslog.Result) {
        fmt.Println(auto.DetectFormat(r.Message))
    }),
    syslog.WithBestEffort(),
)
p.Parse(reader)
```

Things we do not support:

- trailers other than `LF` or `NUL`
- trailers which length is greater than 1 byte
- trailer change on a frame-by-frame basis

### RFC 3195 (BEEP)

[RFC 3195](https://datatracker.ietf.org/doc/html/rfc3195) defines syslog transport over the [BEEP](https://datatracker.ietf.org/doc/html/rfc3080) protocol. It specifies two profiles:

- **RAW** (§4.2): syslog messages are carried as CRLF-terminated payloads in BEEP ANS frames. The inner messages can be either RFC 5424 or RFC 3164 format.
- **COOKED** (§4.3): syslog data is encoded as XML `<entry>` elements with attributes for facility, severity, timestamp, tag, and device identity.

The [rfc3195 package](./rfc3195) provides parsers for both profiles. It implements BEEP frame scanning (MSG, RPY, ERR, ANS, NUL, SEQ frames) and extracts syslog messages from the frame payloads.

This is a parsing-only implementation - it does not handle BEEP session management, channel negotiation, or TLS. Feed it a stream of BEEP frames and it will emit parsed syslog messages.

To quickly understand how to use it please have a look at the [example file](./rfc3195/example_test.go).

## Performances

To run the benchmark execute the following command.

```bash
make bench
```

On my machine<sup>[1](#mymachine)</sup> these are the results obtained paring RFC5424 syslog messages with best effort mode on.

```
[no]_empty_input__________________________________-10  32072733   185.3 ns/op   272 B/op   4 allocs/op
[no]_multiple_syslog_messages_on_multiple_lines___-10  27058381   219.8 ns/op   267 B/op   7 allocs/op
[no]_impossible_timestamp_________________________-10   8732960   683.8 ns/op   555 B/op  12 allocs/op
[no]_malformed_structured_data____________________-10  17997814   335.6 ns/op   499 B/op   8 allocs/op
[no]_with_duplicated_structured_data_id___________-10   9254920   645.7 ns/op   672 B/op  15 allocs/op
[ok]_minimal______________________________________-10  48347473   123.2 ns/op   227 B/op   5 allocs/op
[ok]_average_message______________________________-10   6058492   986.8 ns/op  1344 B/op  20 allocs/op
[ok]_complicated_message__________________________-10   7052536   843.2 ns/op  1232 B/op  23 allocs/op
[ok]_very_long_message____________________________-10   2644068  2279.0 ns/op  2272 B/op  21 allocs/op
[ok]_all_max_length_and_complete__________________-10   3611186  1675.0 ns/op  1848 B/op  27 allocs/op
[ok]_all_max_length_except_structured_data_and_mes-10   5729514  1059.0 ns/op   851 B/op  12 allocs/op
[ok]_minimal_with_message_containing_newline______-10  43165338   142.9 ns/op   230 B/op   6 allocs/op
[ok]_w/o_procid,_w/o_structured_data,_with_message-10  14832892   397.8 ns/op   308 B/op   9 allocs/op
[ok]_minimal_with_UTF-8_message___________________-10  20229313   306.2 ns/op   339 B/op   6 allocs/op
[ok]_minimal_with_UTF-8_message_starting_with_BOM_-10  19721539   306.7 ns/op   355 B/op   6 allocs/op
[ok]_with_structured_data_id,_w/o_structured_data_-10  13860580   435.7 ns/op   538 B/op  10 allocs/op
[ok]_with_multiple_structured_data________________-10   8368731   721.9 ns/op  1173 B/op  15 allocs/op
[ok]_with_escaped_backslash_within_structured_data-10   9730569   632.6 ns/op   864 B/op  16 allocs/op
[ok]_with_UTF-8_structured_data_param_value,_with_-10   8864156   660.6 ns/op   858 B/op  15 allocs/op
```

As you can see it takes:

* ~125ns to parse the smallest legal message

* less than 1µs to parse an average legal message

* ~2µs to parse a very long legal message

Other RFC5424 implementations, like this [one](https://github.com/roguelazer/rust-syslog-rfc5424) in Rust, spend 8µs to parse an average legal message.

---

* <a name="mymachine">[1]</a>: Apple M1 Pro
