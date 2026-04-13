package syslog

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockParser implements syslog.Parser for testing option functions.
type mockParser struct {
	listener         ParserListener
	bestEffort       bool
	maxMessageLength int
	machineOpts      []MachineOption
}

func (m *mockParser) Parse(r io.Reader) {}
func (m *mockParser) HasBestEffort() bool { return m.bestEffort }
func (m *mockParser) WithBestEffort()     { m.bestEffort = true }
func (m *mockParser) WithListener(f ParserListener) {
	m.listener = f
}
func (m *mockParser) WithMaxMessageLength(length int) {
	m.maxMessageLength = length
}
func (m *mockParser) WithMachineOptions(opts ...MachineOption) {
	m.machineOpts = opts
}

func TestWithListener(t *testing.T) {
	called := false
	listener := func(r *Result) { called = true }
	opt := WithListener(listener)
	p := &mockParser{}
	opt(p)
	assert.NotNil(t, p.listener)
	p.listener(&Result{})
	assert.True(t, called)
}

func TestWithMaxMessageLength(t *testing.T) {
	opt := WithMaxMessageLength(2048)
	p := &mockParser{}
	opt(p)
	assert.Equal(t, 2048, p.maxMessageLength)
}

func TestWithMachineOptions(t *testing.T) {
	dummyOpt := func(m Machine) Machine { return m }
	opt := WithMachineOptions(dummyOpt)
	p := &mockParser{}
	opt(p)
	assert.Len(t, p.machineOpts, 1)
}

func TestWithBestEffort(t *testing.T) {
	opt := WithBestEffort()
	p := &mockParser{}
	assert.False(t, p.bestEffort)
	opt(p)
	assert.True(t, p.bestEffort)
}

func TestFacilityLevelFallback(t *testing.T) {
	// Facility value 24 is not in FacilityKeywords, triggering the fallback path
	f := uint8(24)
	b := &Base{Facility: &f}
	result := b.FacilityLevel()
	assert.NotNil(t, result)
	// Value 24 is not in either map, so fallback returns empty string
	assert.Equal(t, "", *result)
}

func TestFacilityLevelNil(t *testing.T) {
	b := &Base{}
	assert.Nil(t, b.FacilityLevel())
}

func TestFacilityLevelValid(t *testing.T) {
	f := uint8(0)
	b := &Base{Facility: &f}
	result := b.FacilityLevel()
	assert.NotNil(t, result)
	assert.Equal(t, "kern", *result)
}

func TestFacilityMessageNil(t *testing.T) {
	b := &Base{}
	assert.Nil(t, b.FacilityMessage())
}

func TestFacilityMessageValid(t *testing.T) {
	f := uint8(0)
	b := &Base{Facility: &f}
	result := b.FacilityMessage()
	assert.NotNil(t, result)
	assert.Equal(t, "kernel messages", *result)
}

func TestSeverityMessageNil(t *testing.T) {
	b := &Base{}
	assert.Nil(t, b.SeverityMessage())
}

func TestSeverityLevelNil(t *testing.T) {
	b := &Base{}
	assert.Nil(t, b.SeverityLevel())
}

func TestSeverityShortLevelNil(t *testing.T) {
	b := &Base{}
	assert.Nil(t, b.SeverityShortLevel())
}

func TestSeverityMessageValid(t *testing.T) {
	s := uint8(0)
	b := &Base{Severity: &s}
	result := b.SeverityMessage()
	assert.NotNil(t, result)
}

func TestSeverityLevelValid(t *testing.T) {
	s := uint8(0)
	b := &Base{Severity: &s}
	result := b.SeverityLevel()
	assert.NotNil(t, result)
}

func TestSeverityShortLevelValid(t *testing.T) {
	s := uint8(0)
	b := &Base{Severity: &s}
	result := b.SeverityShortLevel()
	assert.NotNil(t, result)
}

func TestValid(t *testing.T) {
	p := uint8(1)
	b := &Base{Priority: &p}
	assert.True(t, b.Valid())

	b2 := &Base{}
	assert.False(t, b2.Valid())
}

func TestComputeFromPriority(t *testing.T) {
	b := &Base{}
	b.ComputeFromPriority(34)
	assert.Equal(t, uint8(4), *b.Facility)
	assert.Equal(t, uint8(2), *b.Severity)
	assert.Equal(t, uint8(34), *b.Priority)
}

func TestComputeFromPriorityZero(t *testing.T) {
	b := &Base{}
	b.ComputeFromPriority(0)
	assert.Equal(t, uint8(0), *b.Facility)
	assert.Equal(t, uint8(0), *b.Severity)
}

func TestComputeFromPriorityMax(t *testing.T) {
	b := &Base{}
	b.ComputeFromPriority(191)
	assert.Equal(t, uint8(23), *b.Facility)
	assert.Equal(t, uint8(7), *b.Severity)
}
