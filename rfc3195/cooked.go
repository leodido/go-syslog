package rfc3195

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"time"

	syslog "github.com/leodido/go-syslog/v4"
)

// COOKED profile (RFC 3195 §4.3): syslog messages arrive as <entry> XML
// elements in BEEP frame payloads. Session metadata (<iam>, <path>, <ok/>)
// can optionally be forwarded as raw XML bytes.

// RawElementListener receives raw XML bytes for non-entry elements
// (<iam>, <path>, <ok/>). elementName is the XML local name.
type RawElementListener func(elementName string, rawXML []byte)

// WithRawElementListener returns a parser option that sets a callback for
// COOKED profile metadata elements (<iam>, <path>, <ok/>).
//
// The callback receives the element name and the raw XML bytes of the
// element as they appeared in the BEEP frame payload. go-syslog does not
// define Go types for these elements; a future go-beep library can
// unmarshal them as needed.
//
// If not set, metadata elements are silently skipped.
func WithRawElementListener(f RawElementListener) syslog.ParserOption {
	return func(p syslog.Parser) syslog.Parser {
		p.(*cookedParser).rawEmit = f
		return p
	}
}

// WithCookedYear returns a parser option that sets the year for parsed
// timestamps. RFC 3164 timestamps (used in COOKED <entry> elements) do
// not include a year; without this option the year defaults to 0.
func WithCookedYear(year int) syslog.ParserOption {
	return func(p syslog.Parser) syslog.Parser {
		p.(*cookedParser).year = year
		return p
	}
}

// WithCookedTimezone returns a parser option that sets the timezone for
// parsed timestamps. When set, timestamps are interpreted in the given
// location instead of UTC.
func WithCookedTimezone(loc *time.Location) syslog.ParserOption {
	return func(p syslog.Parser) syslog.Parser {
		p.(*cookedParser).timezone = loc
		return p
	}
}

// cookedParser implements syslog.Parser for the RFC 3195 COOKED profile.
type cookedParser struct {
	bestEffort       bool
	maxMessageLength int
	emit             syslog.ParserListener
	rawEmit          RawElementListener
	year             int
	timezone         *time.Location
}

// NewCookedParser returns a syslog.Parser for the RFC 3195 COOKED profile.
func NewCookedParser(opts ...syslog.ParserOption) syslog.Parser {
	p := &cookedParser{
		emit: func(*syslog.Result) { /* noop */ },
	}

	for _, opt := range opts {
		p = opt(p).(*cookedParser)
	}

	return p
}

func (p *cookedParser) WithBestEffort() {
	p.bestEffort = true
}

func (p *cookedParser) HasBestEffort() bool {
	return p.bestEffort
}

func (p *cookedParser) WithMachineOptions(_ ...syslog.MachineOption) {
	// No inner machine — COOKED parses XML attributes directly.
	// Intentional no-op.
}

func (p *cookedParser) WithMaxMessageLength(length int) {
	p.maxMessageLength = length
}

func (p *cookedParser) WithListener(f syslog.ParserListener) {
	p.emit = f
}

// Parse reads BEEP frames from r and emits parsed syslog messages.
//
// Per RFC 3195 §4.3, the COOKED profile carries syslog messages as <entry>
// XML elements in frame payloads. Metadata elements (<iam>, <path>, <ok/>)
// are forwarded to the RawElementListener if set, otherwise silently skipped.
func (p *cookedParser) Parse(r io.Reader) {
	var scanOpts []ScannerOption
	if p.maxMessageLength > 0 {
		scanOpts = append(scanOpts, WithMaxPayloadSize(p.maxMessageLength))
	}
	scanner := NewScanner(r, scanOpts...)

	for {
		frame, err := scanner.Scan()
		if err != nil {
			if err == io.EOF {
				return
			}
			p.emit(&syslog.Result{
				Error: fmt.Errorf("rfc3195 cooked: frame scan error: %w", err),
			})
			return
		}

		switch frame.Type {
		case FrameANS, FrameMSG:
			p.processPayload(frame.Payload)

		case FrameNUL:
			return

		case FrameERR:
			p.emit(&syslog.Result{
				Error: fmt.Errorf("rfc3195 cooked: received ERR frame: %s", frame.Payload),
			})
			return

		case FrameSEQ:
			continue

		default:
			continue
		}
	}
}

// xmlElement is a lightweight struct for element name detection.
// Metadata elements (<iam>, <path>, <ok/>) are forwarded as raw bytes
// and never need attribute parsing, so we avoid the cost of a full unmarshal.
type xmlElement struct {
	XMLName xml.Name `xml:""`
}

// xmlEntry maps to the <entry> element attributes per RFC 3195 §7 DTD.
// The xml:lang attribute defined in the DTD is intentionally not captured:
// encoding/xml silently ignores unmapped attributes, and language tagging
// is not part of the syslog.Message contract.
type xmlEntry struct {
	XMLName    xml.Name `xml:""`
	Facility   string   `xml:"facility,attr"`
	Severity   string   `xml:"severity,attr"`
	Timestamp  string   `xml:"timestamp,attr"`
	Tag        string   `xml:"tag,attr"`
	DeviceFQDN string   `xml:"deviceFQDN,attr"`
	DeviceIP   string   `xml:"deviceIP,attr"`
	PathID     string   `xml:"pathID,attr"`
	Content    string   `xml:",chardata"`
}

// processPayload parses the XML payload from a BEEP frame.
// For <entry> elements it performs a full unmarshal to extract attributes.
// For metadata elements (<iam>, <path>, <ok/>) it only reads the element
// name and forwards the raw bytes — no attribute parsing needed.
func (p *cookedParser) processPayload(payload []byte) {
	if len(payload) == 0 {
		return
	}

	// Detect element name with a lightweight unmarshal (no attributes populated).
	var elem xmlElement
	if err := xml.Unmarshal(payload, &elem); err != nil {
		p.emit(&syslog.Result{
			Error: fmt.Errorf("rfc3195 cooked: invalid XML: %w", err),
		})
		return
	}

	switch elem.XMLName.Local {
	case "entry":
		var entry xmlEntry
		// Well-formedness was validated above; this extracts attributes.
		xml.Unmarshal(payload, &entry) //nolint:errcheck
		p.processEntry(entry)
	case "iam", "path", "ok":
		if p.rawEmit != nil {
			p.rawEmit(elem.XMLName.Local, payload)
		}
	default:
		// Unknown elements silently skipped
	}
}

// processEntry converts a parsed xmlEntry into a CookedMessage.
func (p *cookedParser) processEntry(entry xmlEntry) {
	msg := &CookedMessage{}

	// facility (required)
	// DTD: %FACILITY = 1*3DIGIT. RFC 3195 examples use values beyond
	// RFC 3164's 0-23 range (e.g., facility='80'). Accept 0-255 (uint8).
	fac, err := strconv.Atoi(entry.Facility)
	if err != nil || fac < 0 || fac > 255 {
		p.emitError(fmt.Errorf("rfc3195 cooked: invalid facility %q", entry.Facility), msg)
		return
	}

	// severity (required)
	// DTD: %SEVERITY = DIGIT (0-9). Accept 0-9 per DTD.
	sev, err := strconv.Atoi(entry.Severity)
	if err != nil || sev < 0 || sev > 9 {
		p.emitError(fmt.Errorf("rfc3195 cooked: invalid severity %q", entry.Severity), msg)
		return
	}

	// ComputeFromPriority sets Priority, Facility, and Severity in one call.
	msg.ComputeFromPriority(uint8(fac)*8 + uint8(sev))

	// timestamp (optional)
	if entry.Timestamp != "" {
		var t time.Time
		var err error
		if p.timezone != nil {
			t, err = time.ParseInLocation(time.Stamp, entry.Timestamp, p.timezone)
		} else {
			t, err = time.Parse(time.Stamp, entry.Timestamp)
		}
		if err != nil {
			p.emitError(fmt.Errorf("rfc3195 cooked: invalid timestamp %q: %w", entry.Timestamp, err), msg)
			return
		}
		if p.year > 0 {
			t = t.AddDate(p.year, 0, 0)
		}
		msg.Timestamp = &t
	}

	// tag → Appname
	if entry.Tag != "" {
		msg.Appname = &entry.Tag
	}

	// hostname derived from deviceFQDN (preferred) or deviceIP (fallback)
	if entry.DeviceFQDN != "" {
		msg.Hostname = &entry.DeviceFQDN
		msg.DeviceFQDN = &entry.DeviceFQDN
	}
	if entry.DeviceIP != "" {
		msg.DeviceIP = &entry.DeviceIP
		if msg.Hostname == nil {
			msg.Hostname = &entry.DeviceIP
		}
	}

	// pathID
	if entry.PathID != "" {
		msg.PathID = &entry.PathID
	}

	// message content
	if entry.Content != "" {
		msg.Message = &entry.Content
	}

	p.emit(&syslog.Result{Message: msg})
}

// emitError emits a parse error, optionally including the partial message
// in best-effort mode.
func (p *cookedParser) emitError(err error, partial *CookedMessage) {
	if p.bestEffort {
		p.emit(&syslog.Result{Message: partial, Error: err})
	} else {
		p.emit(&syslog.Result{Error: err})
	}
}
