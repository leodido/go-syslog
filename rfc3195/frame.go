package rfc3195

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
)

// FrameType represents the type of a BEEP frame (RFC 3080 §2.2.1).
type FrameType int

const (
	FrameMSG FrameType = iota
	FrameRPY
	FrameERR
	FrameANS
	FrameNUL
	FrameSEQ
)

var frameTypeNames = [...]string{"MSG", "RPY", "ERR", "ANS", "NUL", "SEQ"}

func (ft FrameType) String() string {
	if int(ft) < len(frameTypeNames) {
		return frameTypeNames[ft]
	}
	return fmt.Sprintf("FrameType(%d)", int(ft))
}

var keywordToType = map[string]FrameType{
	"MSG": FrameMSG,
	"RPY": FrameRPY,
	"ERR": FrameERR,
	"ANS": FrameANS,
	"NUL": FrameNUL,
	"SEQ": FrameSEQ,
}

// Frame represents a parsed BEEP frame.
type Frame struct {
	Type    FrameType
	Channel uint32
	Msgno   uint32
	More    bool   // '*' = true (intermediate), '.' = false (complete)
	Seqno   uint32
	Size    uint32
	Ansno   uint32 // only meaningful for ANS frames
	Payload []byte // exactly Size bytes; nil for SEQ frames

	// SEQ frame fields (RFC 3081 §3.1.3)
	Ackno  uint32 // only meaningful for SEQ frames
	Window uint32 // only meaningful for SEQ frames
}

// Scanner reads BEEP frames from an io.Reader.
type Scanner struct {
	r *bufio.Reader
}

// NewScanner creates a Scanner that reads BEEP frames from r.
func NewScanner(r io.Reader) *Scanner {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &Scanner{r: br}
}

// Scan reads the next BEEP frame from the underlying reader.
// Returns io.EOF when no more frames are available.
func (s *Scanner) Scan() (Frame, error) {
	line, err := s.r.ReadBytes('\n')
	if err != nil {
		if err == io.EOF && len(line) == 0 {
			return Frame{}, io.EOF
		}
		return Frame{}, fmt.Errorf("reading frame header: %w", err)
	}

	// Strip trailing CRLF
	if len(line) < 2 || line[len(line)-2] != '\r' || line[len(line)-1] != '\n' {
		return Frame{}, fmt.Errorf("frame header missing CRLF terminator")
	}
	line = line[:len(line)-2]

	fields := bytes.Fields(line)
	if len(fields) < 1 {
		return Frame{}, fmt.Errorf("empty frame header")
	}

	keyword := string(fields[0])
	ft, ok := keywordToType[keyword]
	if !ok {
		return Frame{}, fmt.Errorf("unknown frame keyword: %q", keyword)
	}

	if ft == FrameSEQ {
		return s.parseSEQ(fields)
	}

	return s.parseDataFrame(ft, fields)
}

// parseSEQ parses a SEQ frame: SEQ channel ackno window CRLF
// SEQ frames have no payload and no END trailer.
func (s *Scanner) parseSEQ(fields [][]byte) (Frame, error) {
	if len(fields) != 4 {
		return Frame{}, fmt.Errorf("SEQ frame requires 4 fields, got %d", len(fields))
	}

	channel, err := parseUint32(fields[1], "channel")
	if err != nil {
		return Frame{}, err
	}
	ackno, err := parseUint32(fields[2], "ackno")
	if err != nil {
		return Frame{}, err
	}
	window, err := parseUint32(fields[3], "window")
	if err != nil {
		return Frame{}, err
	}

	return Frame{
		Type:    FrameSEQ,
		Channel: channel,
		Ackno:   ackno,
		Window:  window,
	}, nil
}

// parseDataFrame parses MSG, RPY, ERR, ANS, or NUL frames.
// Format: keyword channel msgno more seqno size [ansno] CRLF payload END CRLF
func (s *Scanner) parseDataFrame(ft FrameType, fields [][]byte) (Frame, error) {
	expectedFields := 6
	if ft == FrameANS {
		expectedFields = 7
	}
	if len(fields) != expectedFields {
		return Frame{}, fmt.Errorf("%s frame requires %d fields, got %d", ft, expectedFields, len(fields))
	}

	channel, err := parseUint32(fields[1], "channel")
	if err != nil {
		return Frame{}, err
	}
	msgno, err := parseUint32(fields[2], "msgno")
	if err != nil {
		return Frame{}, err
	}

	more, err := parseContinuation(fields[3])
	if err != nil {
		return Frame{}, err
	}

	seqno, err := parseUint32(fields[4], "seqno")
	if err != nil {
		return Frame{}, err
	}
	size, err := parseUint32(fields[5], "size")
	if err != nil {
		return Frame{}, err
	}

	var ansno uint32
	if ft == FrameANS {
		ansno, err = parseUint32(fields[6], "ansno")
		if err != nil {
			return Frame{}, err
		}
	}

	// Read exactly 'size' bytes of payload
	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(s.r, payload); err != nil {
			return Frame{}, fmt.Errorf("reading payload (%d bytes): %w", size, err)
		}
	}

	// Consume END\r\n trailer
	trailer := make([]byte, 5) // "END\r\n"
	if _, err := io.ReadFull(s.r, trailer); err != nil {
		return Frame{}, fmt.Errorf("reading END trailer: %w", err)
	}
	if string(trailer) != "END\r\n" {
		return Frame{}, fmt.Errorf("expected END trailer, got %q", trailer)
	}

	return Frame{
		Type:    ft,
		Channel: channel,
		Msgno:   msgno,
		More:    more,
		Seqno:   seqno,
		Size:    size,
		Ansno:   ansno,
		Payload: payload,
	}, nil
}

func parseUint32(b []byte, name string) (uint32, error) {
	v, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, b, err)
	}
	return uint32(v), nil
}

func parseContinuation(b []byte) (bool, error) {
	if len(b) != 1 {
		return false, fmt.Errorf("invalid continuation indicator %q", b)
	}
	switch b[0] {
	case '*':
		return true, nil
	case '.':
		return false, nil
	default:
		return false, fmt.Errorf("invalid continuation indicator %q, expected '*' or '.'", b)
	}
}
