package rfc3195

import (
	"bytes"
	"fmt"
	"io"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

// RAW profile (RFC 3195 §4.2): syslog messages arrive as ANS frame payloads,
// each terminated by CRLF. A NUL frame signals end of the exchange.

// parser implements syslog.Parser for the RFC 3195 RAW profile.
type parser struct {
	bestEffort       bool
	maxMessageLength int
	internal         syslog.Machine
	internalOpts     []syslog.MachineOption
	emit             syslog.ParserListener
}

// NewParser returns a syslog.Parser for the RFC 3195 RAW profile using RFC 5424 message format.
func NewParser(opts ...syslog.ParserOption) syslog.Parser {
	p := &parser{
		emit:             func(*syslog.Result) { /* noop */ },
		maxMessageLength: 0, // 0 = no limit
	}

	for _, opt := range opts {
		p = opt(p).(*parser)
	}

	if p.bestEffort {
		p.internalOpts = append(p.internalOpts, rfc5424.WithBestEffort())
	}

	p.internal = rfc5424.NewMachine(p.internalOpts...)

	return p
}

// NewParserRFC3164 returns a syslog.Parser for the RFC 3195 RAW profile using RFC 3164 message format.
func NewParserRFC3164(opts ...syslog.ParserOption) syslog.Parser {
	p := &parser{
		emit:             func(*syslog.Result) { /* noop */ },
		maxMessageLength: 0,
	}

	for _, opt := range opts {
		p = opt(p).(*parser)
	}

	if p.bestEffort {
		p.internalOpts = append(p.internalOpts, rfc3164.WithBestEffort())
	}

	p.internal = rfc3164.NewMachine(p.internalOpts...)

	return p
}

func (p *parser) WithBestEffort() {
	p.bestEffort = true
}

func (p *parser) HasBestEffort() bool {
	return p.bestEffort
}

func (p *parser) WithMachineOptions(opts ...syslog.MachineOption) {
	p.internalOpts = append(p.internalOpts, opts...)
}

func (p *parser) WithMaxMessageLength(length int) {
	p.maxMessageLength = length
}

func (p *parser) WithListener(f syslog.ParserListener) {
	p.emit = f
}

// Parse reads BEEP frames from r and emits parsed syslog messages.
//
// Per RFC 3195 §4.2, the RAW profile carries syslog messages in ANS frame
// payloads. Each payload contains a single syslog message terminated by CRLF.
// A NUL frame signals the end of the exchange. SEQ frames are silently skipped
// (flow control is not relevant for parsing-only use).
func (p *parser) Parse(r io.Reader) {
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
				Error: fmt.Errorf("rfc3195 raw: frame scan error: %w", err),
			})
			return
		}

		switch frame.Type {
		case FrameANS:
			p.processANS(frame)

		case FrameNUL:
			// End of exchange
			return

		case FrameSEQ:
			// Flow control — skip silently
			continue

		default:
			// MSG, RPY, ERR frames are not expected in RAW profile data flow
			// but we skip them rather than aborting
			continue
		}
	}
}

// processANS extracts the syslog message from an ANS frame payload.
// Per RFC 3195 §4.2, the payload is a syslog message terminated by CRLF.
func (p *parser) processANS(frame Frame) {
	payload := frame.Payload

	// Strip exactly one trailing CRLF (framing artifact, not part of the syslog message)
	payload = bytes.TrimSuffix(payload, []byte("\r\n"))

	if len(payload) == 0 {
		return
	}

	msg, err := p.internal.Parse(payload)
	result := &syslog.Result{Message: msg, Error: err}

	if p.bestEffort || err == nil {
		p.emit(result)
	} else {
		p.emit(&syslog.Result{Error: err})
	}
}
