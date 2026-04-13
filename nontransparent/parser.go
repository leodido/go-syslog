package nontransparent

import (
	"io"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/auto"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
	parser "github.com/leodido/ragel-machinery/parser"
)

const nontransparentStart int = 1
const nontransparentError int = 0

const nontransparentEnMain int = 1

type machine struct {
	trailertyp   TrailerType // default is 0 thus TrailerType(LF)
	trailer      byte
	candidate    []byte
	bestEffort   bool
	internal     syslog.Machine
	internalOpts []syslog.MachineOption
	emit         syslog.ParserListener
	readError    error
	lastChunk    []byte // store last candidate message also if it does not ends with a trailer
	// auto-detect fields
	rfc3164Opts []syslog.MachineOption
	rfc5424Opts []syslog.MachineOption
	noFallback  bool
}

// Exec implements the ragel.Parser interface.
func (m *machine) Exec(s *parser.State) (int, int) {
	// Retrieve previously stored parsing variables
	cs, p, pe, eof, data := s.Get()
	{
		var _widec int16
		if p == pe {
			goto _testEof
		}
		switch cs {
		case 1:
			goto stCase1
		case 0:
			goto stCase0
		case 2:
			goto stCase2
		case 3:
			goto stCase3
		}
		goto stOut
	stCase1:
		if data[p] == 60 {
			goto tr0
		}
		goto st0
	stCase0:
	st0:
		cs = 0
		goto _out
	tr0:

		if len(m.candidate) > 0 {
			m.process()
		}
		m.candidate = make([]byte, 0)

		goto st2
	st2:
		if p++; p == pe {
			goto _testEof2
		}
	stCase2:
		_widec = int16(data[p])
		switch {
		case data[p] > 0:
			if 10 <= data[p] && data[p] <= 10 {
				_widec = 256 + (int16(data[p]) - 0)
				if m.trailertyp == LF {
					_widec += 256
				}
			}
		default:
			_widec = 768 + (int16(data[p]) - 0)
			if m.trailertyp == NUL {
				_widec += 256
			}
		}
		switch _widec {
		case 266:
			goto st2
		case 522:
			goto tr3
		case 768:
			goto st2
		case 1024:
			goto tr3
		}
		switch {
		case _widec > 9:
			if 11 <= _widec {
				goto st2
			}
		case _widec >= 1:
			goto st2
		}
		goto st0
	tr3:

		m.candidate = append(m.candidate, data...)

		goto st3
	st3:
		if p++; p == pe {
			goto _testEof3
		}
	stCase3:
		_widec = int16(data[p])
		switch {
		case data[p] > 0:
			if 10 <= data[p] && data[p] <= 10 {
				_widec = 256 + (int16(data[p]) - 0)
				if m.trailertyp == LF {
					_widec += 256
				}
			}
		default:
			_widec = 768 + (int16(data[p]) - 0)
			if m.trailertyp == NUL {
				_widec += 256
			}
		}
		switch _widec {
		case 60:
			goto tr0
		case 266:
			goto st2
		case 522:
			goto tr3
		case 768:
			goto st2
		case 1024:
			goto tr3
		}
		switch {
		case _widec > 9:
			if 11 <= _widec {
				goto st2
			}
		case _widec >= 1:
			goto st2
		}
		goto st0
	stOut:
	_testEof2:
		cs = 2
		goto _testEof
	_testEof3:
		cs = 3
		goto _testEof

	_testEof:
		{
		}
	_out:
		{
		}
	}
	// Update parsing variables
	s.Set(cs, p, pe, eof)
	return p, pe
}

func (m *machine) OnErr(chunk []byte, err error) {
	// Store the last chunk of bytes ending without a trailer - ie., unexpected EOF from the reader
	m.lastChunk = chunk
	m.readError = err
}

func (m *machine) OnEOF(chunk []byte) {
}

func (m *machine) OnCompletion() {
	if len(m.candidate) > 0 {
		m.process()
	}
	// Try to parse last chunk as a candidate
	if m.readError != nil && len(m.lastChunk) > 0 {
		res, err := m.internal.Parse(m.lastChunk)
		if err == nil && !m.internal.HasBestEffort() {
			res = nil
			err = m.readError
		}
		m.emit(&syslog.Result{
			Message: res,
			Error:   err,
		})
	}
}

// NewParser returns a syslog.Parser suitable to parse syslog messages sent with non-transparent framing - ie. RFC 6587.
func NewParser(options ...syslog.ParserOption) syslog.Parser {
	m := &machine{
		emit: func(*syslog.Result) { /* noop */ },
	}

	for _, opt := range options {
		m = opt(m).(*machine)
	}

	// No error can happens since during its setting we check the trailer type passed in
	trailer, _ := m.trailertyp.Value()
	m.trailer = byte(trailer)

	// If bestEffort flag was set via old API, add it to internalOpts
	if m.bestEffort {
		m.internalOpts = append(m.internalOpts, rfc5424.WithBestEffort())
	}

	// Create internal parser depending on options
	m.internal = rfc5424.NewMachine(m.internalOpts...)

	return m
}

func NewParserRFC3164(options ...syslog.ParserOption) syslog.Parser {
	m := &machine{
		emit: func(*syslog.Result) { /* noop */ },
	}

	for _, opt := range options {
		m = opt(m).(*machine)
	}

	// No error can happens since during its setting we check the trailer type passed in
	trailer, _ := m.trailertyp.Value()
	m.trailer = byte(trailer)

	// If bestEffort flag was set via old API, add it to internalOpts
	if m.bestEffort {
		m.internalOpts = append(m.internalOpts, rfc3164.WithBestEffort())
	}

	// Create internal parser depending on options
	m.internal = rfc3164.NewMachine(m.internalOpts...)

	return m
}

// NewParserAuto returns a syslog.Parser that auto-detects RFC 3164 vs RFC 5424
// format per-message using non-transparent framing (RFC 6587).
//
// Use auto.WithRFC3164MachineOptions and auto.WithRFC5424MachineOptions to
// pass format-specific options. Use auto.WithoutParserFallback to disable
// fallback to the other parser on failure.
func NewParserAuto(options ...syslog.ParserOption) syslog.Parser {
	m := &machine{
		emit: func(*syslog.Result) { /* noop */ },
	}

	for _, opt := range options {
		m = opt(m).(*machine)
	}

	trailer, _ := m.trailertyp.Value()
	m.trailer = byte(trailer)

	// Forward generic machine options (from syslog.WithMachineOptions) to both
	// inner parsers so callers migrating from NewParser get consistent behavior.
	rfc3164Opts := append(append([]syslog.MachineOption{}, m.internalOpts...), m.rfc3164Opts...)
	rfc5424Opts := append(append([]syslog.MachineOption{}, m.internalOpts...), m.rfc5424Opts...)

	autoOpts := []auto.Option{
		auto.WithRFC3164Options(rfc3164Opts...),
		auto.WithRFC5424Options(rfc5424Opts...),
	}
	if m.noFallback {
		autoOpts = append(autoOpts, auto.WithoutFallback())
	}

	m.internal = auto.NewMachine(autoOpts...)
	if m.bestEffort {
		m.internal.WithBestEffort()
	}

	return m
}

// AutoParserConfigurer implementation for auto-detect parser options.
func (m *machine) SetRFC3164Options(opts []syslog.MachineOption) {
	m.rfc3164Opts = append(m.rfc3164Opts, opts...)
}

func (m *machine) SetRFC5424Options(opts []syslog.MachineOption) {
	m.rfc5424Opts = append(m.rfc5424Opts, opts...)
}

func (m *machine) SetNoFallback() {
	m.noFallback = true
}

// WithBestEffort implements the syslog.BestEfforter interface.
func (m *machine) WithBestEffort() {
	m.bestEffort = true
}

// HasBestEffort tells whether the receiving parser has best effort mode on or off.
func (m *machine) HasBestEffort() bool {
	return m.internal.HasBestEffort()
}

// WithMaxMessageLength does nothing for this parser.
func (m *machine) WithMaxMessageLength(length int) {}

// WithTrailer sets the trailer byte used to delimit syslog messages in
// non-transparent framing. Supported values are LF (line feed, default)
// and NUL (null byte). See RFC 6587 §3.4.2.
func WithTrailer(t TrailerType) syslog.ParserOption {
	return func(m syslog.Parser) syslog.Parser {
		if val, err := t.Value(); err == nil {
			m.(*machine).trailer = byte(val)
			m.(*machine).trailertyp = t
		}
		return m
	}
}

// WithMachineOptions configures options for the underlying parsing machine.
func (m *machine) WithMachineOptions(opts ...syslog.MachineOption) {
	m.internalOpts = append(m.internalOpts, opts...)
}

// WithListener implements the syslog.Parser interface.
//
// The generic options uses it.
func (m *machine) WithListener(f syslog.ParserListener) {
	m.emit = f
}

// Parse parses the io.Reader incoming bytes.
//
// It stops parsing when an error regarding RFC 6587 is found.
func (m *machine) Parse(reader io.Reader) {
	r := parser.ArbitraryReader(reader, m.trailer)
	parser.New(r, m, parser.WithStart(1)).Parse()
}

func (m *machine) process() {
	lastByte := len(m.candidate) - 1
	if m.candidate[lastByte] == m.trailer {
		m.candidate = m.candidate[:lastByte]
	}
	res, err := m.internal.Parse(m.candidate)
	m.emit(&syslog.Result{
		Message: res,
		Error:   err,
	})
}
