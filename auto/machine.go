package auto

import (
	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

type machine struct {
	rfc3164Opts []syslog.MachineOption
	rfc5424Opts []syslog.MachineOption
	noFallback  bool
	bestEffort  bool
	// Strict machines for primary detection and fallback.
	m3164 syslog.Machine
	m5424 syslog.Machine
	// Best-effort machines, created only when best-effort is enabled.
	// Used as a last resort after both strict machines fail.
	m3164BE syslog.Machine
	m5424BE syslog.Machine
}

// NewMachine returns a syslog.Machine that auto-detects RFC 3164 vs RFC 5424
// format per-message using peek-based heuristics.
func NewMachine(opts ...Option) syslog.Machine {
	m := &machine{}
	for _, opt := range opts {
		opt(m)
	}

	m.m3164 = rfc3164.NewMachine(m.rfc3164Opts...)
	m.m5424 = rfc5424.NewMachine(m.rfc5424Opts...)

	// If machine options baked best-effort into either inner machine,
	// promote to the auto level so HasBestEffort() reports correctly
	// and the transport layer emits partial results.
	if m.m3164.HasBestEffort() || m.m5424.HasBestEffort() {
		m.WithBestEffort()
	}

	return m
}

// WithBestEffort enables best-effort mode. Strict parsing is still attempted
// first (primary then fallback) so that detection errors are corrected via
// fallback. Best-effort is only used as a last resort when both strict
// parsers fail, recovering partial data from the peek-chosen parser.
func (m *machine) WithBestEffort() {
	m.bestEffort = true
	m.m3164BE = rfc3164.NewMachine(m.rfc3164Opts...)
	m.m3164BE.WithBestEffort()
	m.m5424BE = rfc5424.NewMachine(m.rfc5424Opts...)
	m.m5424BE.WithBestEffort()
}

// HasBestEffort reports whether best-effort mode is enabled.
func (m *machine) HasBestEffort() bool {
	return m.bestEffort
}

// Parse auto-detects the syslog format of input and delegates to the
// appropriate inner machine.
//
// The strategy is:
//  1. Try the peek-chosen (primary) parser in strict mode.
//  2. If that fails and fallback is enabled, try the other parser strict.
//  3. If both strict parsers fail and best-effort is on, try the
//     peek-chosen parser in best-effort mode for partial recovery.
//  4. On complete failure, return a *ParseError with the raw input bytes.
func (m *machine) Parse(input []byte) (syslog.Message, error) {
	format := detect(input)

	var primary, secondary syslog.Machine
	if format == FormatRFC5424 {
		primary = m.m5424
		secondary = m.m3164
	} else {
		primary = m.m3164
		secondary = m.m5424
	}

	// 1. Try primary in strict mode.
	msg, err := primary.Parse(input)
	if msg != nil {
		return msg, err
	}

	// 2. Try fallback in strict mode.
	if !m.noFallback {
		fbMsg, fbErr := secondary.Parse(input)
		if fbMsg != nil {
			return fbMsg, fbErr
		}
	}

	// 3. Try primary in best-effort mode for partial recovery.
	if m.bestEffort {
		var bePrimary syslog.Machine
		if format == FormatRFC5424 {
			bePrimary = m.m5424BE
		} else {
			bePrimary = m.m3164BE
		}
		beMsg, beErr := bePrimary.Parse(input)
		if beMsg != nil {
			return beMsg, beErr
		}
	}

	return nil, &ParseError{
		Err:        err,
		RawMessage: append([]byte(nil), input...),
	}
}

// compile-time interface check
var _ syslog.Machine = (*machine)(nil)
