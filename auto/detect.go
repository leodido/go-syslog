package auto

// detect inspects the bytes after the PRI closing bracket to determine
// whether the input is RFC 5424 or RFC 3164. It returns the detected format.
//
// The function examines at most ~6 bytes past the PRI and runs in O(1) time.
// Decision table:
//   - Letter, space, '*'     → RFC 3164 (month name, leading space, Cisco star)
//   - '0'                    → RFC 3164 (zero-padded or Cisco counter)
//   - 4+ digits              → RFC 3164 (year prefix / long Cisco counter)
//   - 1-3 digits + space     → RFC 5424 (VERSION SP)
//   - 1-3 digits + ':'       → RFC 3164 (Cisco counter)
//   - Default                → RFC 5424
const detectStart int = 1
const detectError int = 0

const detectEnMain int = 1

func detect(input []byte) Format {
	// Default to RFC 5424 (stricter grammar gives clearer errors).
	format := FormatRFC5424
	digitCount := 0

	data := input
	cs, p, pe, eof := 0, 0, len(input), len(input)
	// Silence unused variable warnings for Ragel.
	_ = cs
	_ = eof
	_ = data
	_ = digitCount
	{
		cs = detectStart
	}
	{
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
		case 4:
			goto stCase4
		case 5:
			goto stCase5
		case 6:
			goto stCase6
		case 7:
			goto stCase7
		case 8:
			goto stCase8
		case 9:
			goto stCase9
		case 10:
			goto stCase10
		}
		goto stOut
	stCase1:
		if data[p] == 60 {
			goto st2
		}
		goto st0
	stCase0:
	st0:
		cs = 0
		goto _out
	st2:
		if p++; p == pe {
			goto _testEof2
		}
	stCase2:
		if 48 <= data[p] && data[p] <= 57 {
			goto st3
		}
		goto st0
	st3:
		if p++; p == pe {
			goto _testEof3
		}
	stCase3:
		if data[p] == 62 {
			goto st8
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st4
		}
		goto st0
	st4:
		if p++; p == pe {
			goto _testEof4
		}
	stCase4:
		if data[p] == 62 {
			goto st8
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st5
		}
		goto st0
	st5:
		if p++; p == pe {
			goto _testEof5
		}
	stCase5:
		if data[p] == 62 {
			goto st8
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st6
		}
		goto st0
	st6:
		if p++; p == pe {
			goto _testEof6
		}
	stCase6:
		if data[p] == 62 {
			goto st8
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st7
		}
		goto st0
	st7:
		if p++; p == pe {
			goto _testEof7
		}
	stCase7:
		if data[p] == 62 {
			goto st8
		}
		goto st0
	st8:
		if p++; p == pe {
			goto _testEof8
		}
	stCase8:
		switch data[p] {
		case 32:
			goto tr9
		case 42:
			goto tr9
		case 48:
			goto tr9
		}
		switch {
		case data[p] < 65:
			if 49 <= data[p] && data[p] <= 57 {
				goto tr10
			}
		case data[p] > 90:
			if 97 <= data[p] && data[p] <= 122 {
				goto tr9
			}
		default:
			goto tr9
		}
		goto tr8
	tr8:

		format = FormatRFC5424

		goto st9
	tr9:

		format = FormatRFC3164

		goto st9
	tr12:

		if digitCount >= 4 {
			format = FormatRFC3164
		} else if data[p] == ' ' {
			format = FormatRFC5424
		} else if data[p] == ':' {
			format = FormatRFC3164
		} else {
			format = FormatRFC5424
		}

		goto st9
	st9:
		if p++; p == pe {
			goto _testEof9
		}
	stCase9:
		goto st9
	tr10:

		digitCount++

		goto st10
	st10:
		if p++; p == pe {
			goto _testEof10
		}
	stCase10:
		if 48 <= data[p] && data[p] <= 57 {
			goto tr10
		}
		goto tr12
	stOut:
	_testEof2:
		cs = 2
		goto _testEof
	_testEof3:
		cs = 3
		goto _testEof
	_testEof4:
		cs = 4
		goto _testEof
	_testEof5:
		cs = 5
		goto _testEof
	_testEof6:
		cs = 6
		goto _testEof
	_testEof7:
		cs = 7
		goto _testEof
	_testEof8:
		cs = 8
		goto _testEof
	_testEof9:
		cs = 9
		goto _testEof
	_testEof10:
		cs = 10
		goto _testEof

	_testEof:
		{
		}
		if p == eof {
			switch cs {
			case 8:

				format = FormatRFC5424

			case 10:

				// Truncated digit run at end of input.
				if digitCount >= 4 {
					format = FormatRFC3164
				} else {
					format = FormatRFC5424
				}
			}
		}

	_out:
		{
		}
	}

	return format
}
