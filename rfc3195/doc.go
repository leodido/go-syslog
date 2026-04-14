// Package rfc3195 provides parsers for RFC 3195 syslog transport over BEEP
// (RFC 3080). It supports both the RAW profile (§4.2), which carries syslog
// messages in ANS frame payloads, and the COOKED profile (§4.3), which
// encodes syslog data as XML <entry> elements.
//
// This is a parsing-only implementation. It does not handle BEEP session
// management, channel negotiation, or TLS.
package rfc3195
