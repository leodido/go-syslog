[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)

**Parsers for syslog messages and transports**

> [Blazing fast](#performance) Syslog parsers

_By [@leodido](https://github.com/leodido)_.

_This is the official continuation of influxdata/go-syslog_.

This module includes:

- an [RFC 5424-compliant parser and builder](./rfc5424)
- an [RFC 3164-compliant parser](./rfc3164) for BSD syslog messages
- an [auto-detect parser](./auto) that selects RFC 3164 or RFC 5424 per message
- an [RFC 3195 parser](./rfc3195) for syslog over [BEEP](https://datatracker.ietf.org/doc/html/rfc3195), including RAW and COOKED profiles
- an [octet-counting stream parser](./octetcounting) for [RFC 6587 transparent framing](https://datatracker.ietf.org/doc/html/rfc6587#section-3.4.1)
- a [non-transparent stream parser](./nontransparent) for [RFC 6587 delimiter framing](https://datatracker.ietf.org/doc/html/rfc6587#section-3.4.2)

It can parse syslog messages received over:

- TLS with octet counting ([RFC 5425](https://datatracker.ietf.org/doc/html/rfc5425))
- TCP with non-transparent framing or octet counting ([RFC 6587](https://datatracker.ietf.org/doc/html/rfc6587))
- UDP carrying one message per packet ([RFC 5426](https://datatracker.ietf.org/doc/html/rfc5426))

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

Parse RFC 5424 messages with `rfc5424.NewParser`. The RFC 3164 parser uses the
same interface; its options are demonstrated in
[rfc3164/example_test.go](./rfc3164/example_test.go).

```go
input := []byte(`<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`)
p := rfc5424.NewParser()
msg, err := p.Parse(input)
if err != nil {
    log.Fatal(err)
}

m := msg.(*rfc5424.SyslogMessage)
fmt.Println(*m.Priority, m.Version, *m.Hostname)
// 165 4 mymach.it
```

### Messages without PRI

Both parsers require PRI by default. Use `WithOptionalPriority()` to accept an
otherwise valid message without it:

```go
rfc3164Parser := rfc3164.NewParser(rfc3164.WithOptionalPriority())
rfc5424Parser := rfc5424.NewParser(rfc5424.WithOptionalPriority())
```

When PRI is absent, `Priority`, `Facility`, and `Severity` are nil. Options can
be combined; for example, VMware ESXi messages commonly need both optional PRI
and fractional RFC 3339 timestamps:

```go
esxiParser := rfc3164.NewParser(
    rfc3164.WithOptionalPriority(),
    rfc3164.WithRFC3339(),
)
```

### Best effort mode

With `WithBestEffort()`, a parse error returns the fields collected before the
failure. An RFC 5424 partial result requires PRI and VERSION, or VERSION alone
when `WithOptionalPriority()` is also set.

```go
input := []byte("<1>1 A - - - - - -")
p := rfc5424.NewParser(rfc5424.WithBestEffort())
msg, err := p.Parse(input)
partial := msg.(*rfc5424.SyslogMessage)

fmt.Println(*partial.Priority, partial.Version)
fmt.Println(err)
// 1 1
// expecting a RFC3339MICRO timestamp or a nil value [col 5]
```

Both `msg` and `err` are non-nil because the parser collected a valid partial
RFC 5424 message before the error.

### Builder

Use `SyslogMessage` to construct RFC 5424 messages. `Valid()` checks parser-level
structure; `String()` requires PRI. Setters ignore values that do not match the
grammar.

```go
msg := &rfc5424.SyslogMessage{}
msg.SetTimestamp("invalid timestamp")
fmt.Println(msg.Timestamp == nil, msg.Valid())

msg.SetPriority(191)
msg.SetVersion(1)
str, err := msg.String()

fmt.Println(msg.Valid(), err)
fmt.Println(str)
// true false
// true <nil>
// <191>1 - - - - - -
```

### Auto-detect

Use the [auto](./auto) package when a source mixes RFC 5424 and RFC 3164 messages.

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

For messages without PRI, auto-detection recognizes RFC 3164 timestamps that
start with a three-letter month or a four-digit year followed by `-`. Other
priorityless inputs are tried as RFC 5424 first. Unless `WithoutFallback()` is
set, a complete parse failure causes the other parser to be tried.

## Message transfer

Packet-oriented transports carry one syslog message per packet. Stream
transports use non-transparent or octet-counting framing. This library provides
parsers for both stream formats.

### Octet counting

[RFC 5425](https://datatracker.ietf.org/doc/html/rfc5425#section-4.3) and
[RFC 6587](https://datatracker.ietf.org/doc/html/rfc6587) describe transparent
framing with octet counting. Each message is prefixed with its byte length.

The [octetcounting package](./octetcounting) parses this framing. See its
[examples](./octetcounting/example_test.go).

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

### Non-transparent framing

[RFC 6587](https://datatracker.ietf.org/doc/html/rfc6587#section-3.4.2)
also defines non-transparent framing, in which a delimiter—usually a line
feed—separates messages. The [nontransparent package](./nontransparent) parses
this framing. See its [examples](./nontransparent/example_test.go).

As with octet counting, use `NewParserAuto` for mixed-format streams:

```go
p := nontransparent.NewParserAuto(
    syslog.WithListener(func(r *syslog.Result) {
        fmt.Println(auto.DetectFormat(r.Message))
    }),
    syslog.WithBestEffort(),
)
p.Parse(reader)
```

Unsupported delimiter configurations:

- trailers other than `LF` or `NUL`
- trailers longer than one byte
- changing the trailer between frames

### RFC 3195 (BEEP)

[RFC 3195](https://datatracker.ietf.org/doc/html/rfc3195) defines syslog transport over the [BEEP](https://datatracker.ietf.org/doc/html/rfc3080) protocol. It specifies two profiles:

- **RAW** (§4.2): syslog messages are carried as CRLF-terminated payloads in BEEP ANS frames. The inner messages can be either RFC 5424 or RFC 3164 format.
- **COOKED** (§4.3): syslog data is encoded as XML `<entry>` elements with attributes for facility, severity, timestamp, tag, and device identity.

The [rfc3195 package](./rfc3195) provides parsers for both profiles. It implements BEEP frame scanning (MSG, RPY, ERR, ANS, NUL, SEQ frames) and extracts syslog messages from the frame payloads.

This parser does not handle BEEP session management, channel negotiation, or
TLS. Feed it BEEP frames and it emits parsed syslog messages. See the
[examples](./rfc3195/example_test.go).

## Performance

Run the benchmarks with:

```bash
make bench
```

The following `BenchmarkParse` results were measured on an Apple M4 Pro with
14 logical CPUs, using Go 1.24.4 on `darwin/arm64`. Best-effort mode was enabled;
`make bench` uses a five-second benchmark time.

```
[no]_empty_input__________________________________-14  45358116   127.3 ns/op   272 B/op   4 allocs/op
[no]_multiple_syslog_messages_on_multiple_lines___-14  38895066   154.8 ns/op   283 B/op   7 allocs/op
[no]_impossible_timestamp_________________________-14  12993157   463.4 ns/op   571 B/op  12 allocs/op
[no]_malformed_structured_data____________________-14  25974694   228.3 ns/op   515 B/op   8 allocs/op
[no]_with_duplicated_structured_data_id___________-14  13554434   440.4 ns/op   688 B/op  15 allocs/op
[ok]_minimal______________________________________-14  64324653   91.11 ns/op   243 B/op   5 allocs/op
[ok]_average_message______________________________-14   8714227   704.8 ns/op  1360 B/op  20 allocs/op
[ok]_complicated_message__________________________-14   8980812   625.4 ns/op  1248 B/op  23 allocs/op
[ok]_very_long_message____________________________-14   3569872    1642 ns/op  2288 B/op  21 allocs/op
[ok]_all_max_length_and_complete__________________-14   4835001    1261 ns/op  1864 B/op  27 allocs/op
[ok]_all_max_length_except_structured_data_and_mes-14   7233706   816.2 ns/op   867 B/op  12 allocs/op
[ok]_minimal_with_message_containing_newline______-14  58016277   103.0 ns/op   246 B/op   6 allocs/op
[ok]_w/o_procid,_w/o_structured_data,_with_message-14  22200367   269.7 ns/op   324 B/op   9 allocs/op
[ok]_minimal_with_UTF-8_message___________________-14  28426178   212.2 ns/op   355 B/op   6 allocs/op
[ok]_minimal_with_UTF-8_message_starting_with_BOM_-14  27452876   220.4 ns/op   371 B/op   6 allocs/op
[ok]_with_structured_data_id,_w/o_structured_data_-14  20122576   299.7 ns/op   554 B/op  10 allocs/op
[ok]_with_multiple_structured_data________________-14  11264368   526.1 ns/op  1189 B/op  15 allocs/op
[ok]_with_escaped_backslash_within_structured_data-14  13686079   443.7 ns/op   880 B/op  16 allocs/op
[ok]_with_UTF-8_structured_data_param_value,_with_-14  13543791   439.2 ns/op   874 B/op  15 allocs/op
```

Approximate parsing times:

- 91 ns for the smallest legal message
- 705 ns for an average legal message
- 1.64 µs for a very long legal message
