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

// cookedParser implements syslog.Parser for the RFC 3195 COOKED profile.
type cookedParser struct {
	bestEffort       bool
	maxMessageLength int
	emit             syslog.ParserListener
	rawEmit          RawElementListener
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

// xmlEntry maps to the <entry> element attributes per RFC 3195 §7 DTD.
// Also used for element name detection via XMLName.
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
func (p *cookedParser) processPayload(payload []byte) {
	if len(payload) == 0 {
		return
	}

	var entry xmlEntry
	if err := xml.Unmarshal(payload, &entry); err != nil {
		p.emit(&syslog.Result{
			Error: fmt.Errorf("rfc3195 cooked: invalid XML: %w", err),
		})
		return
	}

	switch entry.XMLName.Local {
	case "entry":
		p.processEntry(entry)
	case "iam", "path", "ok":
		if p.rawEmit != nil {
			p.rawEmit(entry.XMLName.Local, payload)
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
	facU8 := uint8(fac)
	msg.Facility = &facU8

	// severity (required)
	// DTD: %SEVERITY = DIGIT (0-9). Accept 0-9 per DTD.
	sev, err := strconv.Atoi(entry.Severity)
	if err != nil || sev < 0 || sev > 9 {
		p.emitError(fmt.Errorf("rfc3195 cooked: invalid severity %q", entry.Severity), msg)
		return
	}
	sevU8 := uint8(sev)
	msg.Severity = &sevU8

	// priority = facility * 8 + severity
	msg.ComputeFromPriority(facU8*8 + sevU8)
	// ComputeFromPriority overwrites Facility/Severity, but they're the same values

	// timestamp (optional)
	if entry.Timestamp != "" {
		t, err := time.Parse(time.Stamp, entry.Timestamp)
		if err != nil {
			p.emitError(fmt.Errorf("rfc3195 cooked: invalid timestamp %q: %w", entry.Timestamp, err), msg)
			return
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
