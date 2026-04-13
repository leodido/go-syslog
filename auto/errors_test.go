package auto

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseError_Error(t *testing.T) {
	inner := fmt.Errorf("bad format")
	pe := &ParseError{Err: inner, RawMessage: []byte("raw")}
	assert.Equal(t, "auto-detect parse failed: bad format", pe.Error())
}

func TestParseError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	pe := &ParseError{Err: inner, RawMessage: []byte("data")}
	assert.Equal(t, inner, pe.Unwrap())
}

func TestParseError_ErrorsAs(t *testing.T) {
	inner := fmt.Errorf("parse failure")
	pe := &ParseError{Err: inner, RawMessage: []byte("hello")}

	var target *ParseError
	require.True(t, errors.As(pe, &target))
	assert.Equal(t, []byte("hello"), target.RawMessage)
	assert.Equal(t, inner, target.Err)
}

func TestParseError_ErrorsIs(t *testing.T) {
	inner := fmt.Errorf("specific error")
	pe := &ParseError{Err: inner}

	assert.True(t, errors.Is(pe, inner))
}
