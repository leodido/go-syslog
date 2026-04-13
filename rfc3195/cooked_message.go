package rfc3195

import syslog "github.com/leodido/go-syslog/v4"

// CookedMessage represents a syslog message parsed from an RFC 3195
// COOKED profile <entry> element.
//
// It extends syslog.Base with device identity fields (DeviceFQDN,
// DeviceIP) and a PathID that links the entry to a relay path element.
//
// The RFC 3195 DTD allows facility 0–255 and severity 0–9, which extends
// beyond the standard syslog priority range (facility 0–23, severity 0–7).
// For extended-range values, Priority is nil and Valid() returns false even
// though the message was successfully parsed. Use Facility/Severity directly
// instead of Valid() to check parse success.
type CookedMessage struct {
	syslog.Base

	DeviceFQDN *string
	DeviceIP   *string
	PathID     *string
}

// compile-time interface check
var _ syslog.Message = (*CookedMessage)(nil)
