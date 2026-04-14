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

%%{
machine detect;

# unsigned alphabet
alphtype uint8;

action set_3164 {
    format = FormatRFC3164
}

action set_5424 {
    format = FormatRFC5424
}

action count_digit {
    digitCount++
}

action check_after_digits {
    if digitCount >= 4 {
        format = FormatRFC3164
    } else if fc == ' ' {
        format = FormatRFC5424
    } else if fc == ':' {
        format = FormatRFC3164
    } else {
        format = FormatRFC5424
    }
}

action check_eof_digits {
    // Truncated digit run at end of input.
    if digitCount >= 4 {
        format = FormatRFC3164
    } else {
        format = FormatRFC5424
    }
}

# PRI field: '<' 1-5 digits '>'
pri = '<' digit{1,5} '>';

# Non-zero digit
nzdigit = '1'..'9';

# After PRI: immediate classification for non-digit starts.
after_3164_immediate = (alpha | ' ' | '*') @set_3164 any*;
after_3164_zero = '0' @set_3164 any*;

# Digit run: count digits, then classify based on count and following byte.
after_digit_run = (nzdigit $count_digit (digit $count_digit)*)
                  ((any - digit) >check_after_digits any* | '' %check_eof_digits);

# Anything else → RFC 5424.
after_5424_default = (any - alpha - ' ' - '*' - digit) @set_5424 any*;

# Empty after PRI → RFC 5424.
after_5424_empty = '' %set_5424;

after_pri = after_3164_immediate
          | after_3164_zero
          | after_digit_run
          | after_5424_default
          | after_5424_empty;

main := pri after_pri;

}%%

%% write data nofinal;

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

    %% write init;
    %% write exec;

    return format
}
