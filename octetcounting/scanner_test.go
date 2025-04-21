package octetcounting

import "testing"

// testResult holds expected values for each function
type testResult struct {
	isDigit        bool
	isNonZeroDigit bool
}

func TestDigitFunctions(t *testing.T) {
	// Define all test cases with expected results for both functions
	tests := []struct {
		name     string
		char     byte
		expected testResult
	}{
		{"ASCII 0", '0', testResult{true, false}},
		{"ASCII 1", '1', testResult{true, true}},
		{"ASCII 2", '2', testResult{true, true}},
		{"ASCII 3", '3', testResult{true, true}},
		{"ASCII 4", '4', testResult{true, true}},
		{"ASCII 5", '5', testResult{true, true}},
		{"ASCII 6", '6', testResult{true, true}},
		{"ASCII 7", '7', testResult{true, true}},
		{"ASCII 8", '8', testResult{true, true}},
		{"ASCII 9", '9', testResult{true, true}},

		// Edge cases: characters right before and after the digit range
		{"ASCII 47 (/)", '/', testResult{false, false}},
		{"ASCII 58 (:)", ':', testResult{false, false}},

		// Other ASCII characters
		{"Lowercase letter", 'a', testResult{false, false}},
		{"Uppercase letter", 'A', testResult{false, false}},
		{"Special character", '#', testResult{false, false}},
		{"Whitespace", ' ', testResult{false, false}},
		{"Newline", '\n', testResult{false, false}},
		{"Null byte", 0, testResult{false, false}},
		{"Dash", '-', testResult{false, false}},
		{"Plus", '+', testResult{false, false}},
	}

	// Test isDigit
	t.Run("isDigit", func(t *testing.T) {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := isDigit(tc.char)
				if result != tc.expected.isDigit {
					t.Errorf("isDigit(%q) = %v, expected %v", tc.char, result, tc.expected.isDigit)
				}
			})
		}
	})

	// Test isNonZeroDigit
	t.Run("isNonZeroDigit", func(t *testing.T) {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				result := isNonZeroDigit(tc.char)
				if result != tc.expected.isNonZeroDigit {
					t.Errorf("isNonZeroDigit(%q) = %v, expected %v", tc.char, result, tc.expected.isNonZeroDigit)
				}
			})
		}
	})
}
