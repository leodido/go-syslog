package rfc3195

import syslog "github.com/leodido/go-syslog/v4"

// CookedMessage represents a syslog message parsed from an RFC 3195
// COOKED profile <entry> element.
//
// It extends syslog.Base with device identity fields (DeviceFQDN,
// DeviceIP) and a PathID that links the entry to a relay path element.
type CookedMessage struct {
	syslog.Base

	DeviceFQDN *string
	DeviceIP   *string
	PathID     *string
}

// compile-time interface check
var _ syslog.Message = (*CookedMessage)(nil)
