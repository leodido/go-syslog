# RFC 3164 Syslog Parser

This package parses RFC 3164 (BSD syslog) messages. It accepts the standard
format by default and provides the opt-in extensions listed below.

## Message Format

```
<PRI>TIMESTAMP HOSTNAME TAG[PROCID]: MESSAGE
```

```
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
```

## Usage

```go
import "github.com/leodido/go-syslog/v4/rfc3164"

p := rfc3164.NewParser()

msg, err := p.Parse([]byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed"))
if err != nil {
    log.Fatal(err)
}

m := msg.(*rfc3164.SyslogMessage)
fmt.Printf("Priority: %d\n", *m.Priority)
fmt.Printf("Hostname: %s\n", *m.Hostname)
fmt.Printf("Message: %s\n", *m.Message)
```

## Options

### Optional Priority

PRI is required by default. `WithOptionalPriority()` accepts an otherwise valid
message without it:

```go
p := rfc3164.NewParser(rfc3164.WithOptionalPriority())
```

When PRI is absent, `Priority`, `Facility`, and `Severity` are nil. A fully
parsed priorityless message is still valid: `SyslogMessage.Valid()` requires
its timestamp and message fields when no priority is present.

### RFC 3339 Timestamps

`WithRFC3339()` accepts RFC 3339 timestamps in RFC 3164-style messages:

```go
p := rfc3164.NewParser(rfc3164.WithRFC3339())
```

The extension accepts timezone offsets and fractional seconds up to six digits.
Stamp timestamps remain accepted.

### Timezone Configuration

Timestamps without timezone information use UTC by default. To use another
timezone:

```go
loc, _ := time.LoadLocation("America/New_York")
p := rfc3164.NewParser(
    rfc3164.WithTimezone(loc),
)
```

### Year Specification

RFC 3164 timestamps do not include the year. Specify it explicitly:

```go
p := rfc3164.NewParser(
    rfc3164.WithYear(rfc3164.Year{YYYY: 2024}),
)
```

### Best Effort Mode

Parse partial messages when complete parsing fails:

```go
p := rfc3164.NewParser(
    rfc3164.WithBestEffort(),
)
```

### Cisco IOS

Cisco IOS can add fields before the timestamp. Their order is configurable.

```
<PRI>[msgcount:] [sequence:] [hostname:] [*]TIMESTAMP: MESSAGE
```

Example:

```
<189>237: 000485: router1: *Jan 8 19:46:03.295: %LINEPROTO-5-UPDOWN: Line protocol on Interface Loopback100, changed state to up
```

#### Configuration

```go
import (
    "github.com/leodido/go-syslog/v4/rfc3164"
    "github.com/leodido/go-syslog/v4/rfc3164/ciscoios"
)

// Parse all Cisco IOS components
p := rfc3164.NewParser(
    rfc3164.WithCiscoIOSComponents(ciscoios.All),
)

// Selectively disable components
p := rfc3164.NewParser(
    rfc3164.WithCiscoIOSComponents(
        ciscoios.DisableSequenceNumber | ciscoios.DisableHostname,
    ),
)
```

#### Cisco Components

| Component        | Description             | Cisco Command                                                        |
| ---------------- | ----------------------- | -------------------------------------------------------------------- |
| Message Counter  | Remote logging counter  | Enabled by default; disable with `no logging message-counter syslog` |
| Service Sequence | Global message sequence | `service sequence-numbers`                                           |
| Hostname         | Origin hostname         | `logging origin-id hostname`                                         |
| Milliseconds     | Timestamp precision     | `service timestamps log datetime msec`                               |
| Asterisk         | NTP sync indicator      | Appears when NTP not synchronized                                    |

#### Matching Device Configuration

Parser options must match the fields emitted by the device. Numeric components
cannot be distinguished reliably from their values alone.

```go
// Device sends both message counter and sequence number: <189>237: 000485: *Jan 8 19:46:03.295: ...
// Parser configured for message counter only (mismatch):
p := rfc3164.NewParser(
    rfc3164.WithCiscoIOSComponents(ciscoios.DisableSequenceNumber),
)
// Result: Parse error "expecting a sequence number (from 1 to max 255 digits) [col 10]"
// Parser found digits where it expects timestamp, indicating sequence parsing should be enabled.
```

##### Example Device Configuration

```cisco
conf t
! Enable message counter (default for remote logging)
logging host 10.0.0.10

! Add service sequence numbers
service sequence-numbers

! Add origin hostname
logging origin-id hostname

! Enable millisecond timestamps
service timestamps log datetime msec localtime

! Recommended: Enable NTP to remove asterisk
ntp server <your-ntp-server>
```

## Known Limitations

### Format Ambiguities

RFC 3164 leaves several fields underspecified:

- No standard field delimiters beyond whitespace
- Hostname and tag can be ambiguous
- No year in timestamps
- No timezone specification in basic format

### Other Vendor Formats

Unsupported formats tracked in
[issue #61](https://github.com/leodido/go-syslog/issues/61) include:

- BSD-style timestamps that contain a year
- Unix epoch timestamps, including fractional epochs
- named timezone tokens embedded after a timestamp, such as `IST` or `SST`
- counter, hostname, or task fields outside the supported Cisco IOS ordering
- RFC 5424-like envelopes that use an `app[pid]:` tag instead of separate fields

### Cisco IOS Limitations

- Component ordering must match the parser options. A mismatch can fail parsing
  or assign fields incorrectly.
- RFC 5424-style structured data from `logging host X session-id` or
  `sequence-num-session` is not supported. See issue #35.
