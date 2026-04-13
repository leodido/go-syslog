package rfc3195

import (
	"fmt"
	"strconv"
)

// beepFrame builds a raw BEEP data frame string.
// Size is computed automatically from len(payload).
// For ANS frames, pass ansno >= 0. For other types, ansno is ignored.
func beepFrame(keyword string, channel, msgno int, more byte, seqno int, ansno int, payload string) string {
	size := len(payload)
	header := fmt.Sprintf("%s %d %d %c %d %d", keyword, channel, msgno, more, seqno, size)
	if keyword == "ANS" {
		header += " " + strconv.Itoa(ansno)
	}
	return header + "\r\n" + payload + "END\r\n"
}

func seqFrame(channel, ackno, window int) string {
	return fmt.Sprintf("SEQ %d %d %d\r\n", channel, ackno, window)
}
