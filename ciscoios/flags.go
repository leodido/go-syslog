package ciscoios

type Component int

const (
	All                    Component = 0
	DisableMessageCounter  Component = 0x01
	DisableSequenceNumber  Component = 0x02
	DisableHostname        Component = 0x04
	DisableSecondFractions Component = 0x08
)
