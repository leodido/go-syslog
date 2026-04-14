package auto

import (
	"io"
	"testing"

	syslog "github.com/leodido/go-syslog/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAutoParser implements syslog.Parser and AutoParserConfigurer for testing.
type mockAutoParser struct {
	rfc3164Opts []syslog.MachineOption
	rfc5424Opts []syslog.MachineOption
	noFallback  bool
}

func (m *mockAutoParser) Parse(io.Reader)                          {}
func (m *mockAutoParser) WithListener(syslog.ParserListener)       {}
func (m *mockAutoParser) WithBestEffort()                          {}
func (m *mockAutoParser) HasBestEffort() bool                      { return false }
func (m *mockAutoParser) WithMachineOptions(...syslog.MachineOption) {}
func (m *mockAutoParser) WithMaxMessageLength(int)                 {}

func (m *mockAutoParser) SetRFC3164Options(opts []syslog.MachineOption) {
	m.rfc3164Opts = append(m.rfc3164Opts, opts...)
}

func (m *mockAutoParser) SetRFC5424Options(opts []syslog.MachineOption) {
	m.rfc5424Opts = append(m.rfc5424Opts, opts...)
}

func (m *mockAutoParser) SetNoFallback() {
	m.noFallback = true
}

// mockPlainParser implements syslog.Parser but NOT AutoParserConfigurer.
type mockPlainParser struct{}

func (m *mockPlainParser) Parse(io.Reader)                          {}
func (m *mockPlainParser) WithListener(syslog.ParserListener)       {}
func (m *mockPlainParser) WithBestEffort()                          {}
func (m *mockPlainParser) HasBestEffort() bool                      { return false }
func (m *mockPlainParser) WithMachineOptions(...syslog.MachineOption) {}
func (m *mockPlainParser) WithMaxMessageLength(int)                 {}

func TestWithRFC3164MachineOptions_Configurer(t *testing.T) {
	dummyOpt := func(m syslog.Machine) syslog.Machine { return m }
	opt := WithRFC3164MachineOptions(dummyOpt)

	p := &mockAutoParser{}
	result := opt(p)

	assert.Same(t, p, result)
	assert.Len(t, p.rfc3164Opts, 1)
}

func TestWithRFC3164MachineOptions_NonConfigurer(t *testing.T) {
	dummyOpt := func(m syslog.Machine) syslog.Machine { return m }
	opt := WithRFC3164MachineOptions(dummyOpt)

	p := &mockPlainParser{}
	result := opt(p)

	assert.Same(t, p, result)
}

func TestWithRFC5424MachineOptions_Configurer(t *testing.T) {
	dummyOpt := func(m syslog.Machine) syslog.Machine { return m }
	opt := WithRFC5424MachineOptions(dummyOpt)

	p := &mockAutoParser{}
	result := opt(p)

	assert.Same(t, p, result)
	assert.Len(t, p.rfc5424Opts, 1)
}

func TestWithRFC5424MachineOptions_NonConfigurer(t *testing.T) {
	dummyOpt := func(m syslog.Machine) syslog.Machine { return m }
	opt := WithRFC5424MachineOptions(dummyOpt)

	p := &mockPlainParser{}
	result := opt(p)

	assert.Same(t, p, result)
}

func TestWithoutParserFallback_Configurer(t *testing.T) {
	opt := WithoutParserFallback()

	p := &mockAutoParser{}
	result := opt(p)

	assert.Same(t, p, result)
	assert.True(t, p.noFallback)
}

func TestWithoutParserFallback_NonConfigurer(t *testing.T) {
	opt := WithoutParserFallback()

	p := &mockPlainParser{}
	result := opt(p)

	assert.Same(t, p, result)
}

func TestSafeMachineOptions_RecoversPanic(t *testing.T) {
	// An option that panics on the wrong machine type.
	panickingOpt := func(m syslog.Machine) syslog.Machine {
		panic("wrong machine type")
	}

	safe := SafeMachineOptions([]syslog.MachineOption{panickingOpt})
	require.Len(t, safe, 1)

	// Should not panic; machine returned unchanged.
	m := NewMachine()
	assert.NotPanics(t, func() {
		result := safe[0](m)
		assert.Equal(t, m, result)
	})
}

func TestSafeMachineOptions_PassesThrough(t *testing.T) {
	// An option that works normally.
	called := false
	normalOpt := func(m syslog.Machine) syslog.Machine {
		called = true
		return m
	}

	safe := SafeMachineOptions([]syslog.MachineOption{normalOpt})
	m := NewMachine()
	safe[0](m)
	assert.True(t, called)
}

func TestSafeMachineOptions_Empty(t *testing.T) {
	safe := SafeMachineOptions(nil)
	assert.Empty(t, safe)
}
