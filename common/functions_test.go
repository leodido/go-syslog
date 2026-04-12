package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleUTF8DecimalConversion(t *testing.T) {
	slice := []uint8{49, 48, 49}
	res := UnsafeUTF8DecimalCodePointsToInt(slice)
	assert.Equal(t, 101, res)
}

func TestNumberStartingWithZero(t *testing.T) {
	slice := []uint8{48, 48, 50}
	res := UnsafeUTF8DecimalCodePointsToInt(slice)
	assert.Equal(t, 2, res)
}

func TestCharsNotInRange(t *testing.T) {
	point := 10
	slice := []uint8{uint8(point)} // Line Feed (LF)
	res := UnsafeUTF8DecimalCodePointsToInt(slice)
	assert.Equal(t, res, -(48 - point))
}

func TestAllDigits(t *testing.T) {
	slice := []uint8{49, 50, 51, 52, 53, 54, 55, 56, 57, 48}
	res := UnsafeUTF8DecimalCodePointsToInt(slice)
	assert.Equal(t, 1234567890, res)
}

func TestRemoveBytes(t *testing.T) {
	data := []byte(`hello\world`)
	res := RemoveBytes(data, []int{5}, 0)
	assert.Equal(t, []byte(`helloworld`), res)

	// Multiple positions
	data2 := []byte(`a\b\c`)
	res2 := RemoveBytes(data2, []int{1, 3}, 0)
	assert.Equal(t, []byte(`abc`), res2)

	// With offset
	data3 := []byte(`xx\yy`)
	res3 := RemoveBytes(data3, []int{4}, 2)
	assert.Equal(t, []byte(`xxyy`), res3)

	// Original data is not modified
	orig := []byte(`a\b`)
	RemoveBytes(orig, []int{1}, 0)
	assert.Equal(t, []byte(`a\b`), orig)
}

func TestEscapeBytes(t *testing.T) {
	assert.Equal(t, `\\`, EscapeBytes(`\`))
	assert.Equal(t, `\]`, EscapeBytes(`]`))
	assert.Equal(t, `\"`, EscapeBytes(`"`))
	assert.Equal(t, `hello`, EscapeBytes(`hello`))
	assert.Equal(t, `a\\b\]c\"d`, EscapeBytes(`a\b]c"d`))
	assert.Equal(t, ``, EscapeBytes(``))
}

func TestInBetween(t *testing.T) {
	assert.True(t, InBetween(5, 1, 10))
	assert.True(t, InBetween(1, 1, 10))
	assert.True(t, InBetween(10, 1, 10))
	assert.False(t, InBetween(0, 1, 10))
	assert.False(t, InBetween(11, 1, 10))
}

func TestValidPriority(t *testing.T) {
	assert.True(t, ValidPriority(0))
	assert.True(t, ValidPriority(191))
	assert.True(t, ValidPriority(100))
	assert.False(t, ValidPriority(192))
	assert.False(t, ValidPriority(255))
}

func TestValidVersion(t *testing.T) {
	assert.True(t, ValidVersion(1))
	assert.True(t, ValidVersion(999))
	assert.True(t, ValidVersion(500))
	assert.False(t, ValidVersion(0))
	assert.False(t, ValidVersion(1000))
}
