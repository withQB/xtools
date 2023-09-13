package xtools

import (
	"context"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/withqb/xtools/spec"
)

// FrameVersion refers to the frame version for a specific frame.
type FrameVersion string

type IFrameVersion interface {
	Version() FrameVersion
	Stable() bool
	StateResAlgorithm() StateResAlgorithm
	EventFormat() EventFormat
	EventIDFormat() EventIDFormat
	RedactEventJSON(eventJSON []byte) ([]byte, error)
	SignatureValidityCheck(atTS, validUntil spec.Timestamp) bool
	NewEventFromTrustedJSON(eventJSON []byte, redacted bool) (result PDU, err error)
	NewEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool) (result PDU, err error)
	NewEventFromUntrustedJSON(eventJSON []byte) (result PDU, err error)
	NewEventBuilder() *EventBuilder
	NewEventBuilderFromProtoEvent(pe *ProtoEvent) *EventBuilder
	CheckRestrictedJoin(ctx context.Context, localServerName spec.ServerName, frameQuerier RestrictedFrameJoinQuerier, frameID spec.FrameID, senderID spec.SenderID) (string, error)

	RestrictedJoinServername(content []byte) (spec.ServerName, error)
	CheckRestrictedJoinsAllowed() error
	CheckKnockingAllowed(m *membershipAllower) error
	CheckNotificationLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error
	CheckCanonicalJSON(input []byte) error
	ParsePowerLevels(contentBytes []byte, c *PowerLevelContent) error
}

// StateResAlgorithm refers to a version of the state resolution algorithm.
type StateResAlgorithm int

// EventFormat refers to the formatting of the event fields struct.
type EventFormat int

// EventIDFormat refers to the formatting used to generate new event IDs.
type EventIDFormat int

// Frame version constants. These are strings because the version grammar
// allows for future expansion.
const (
	FrameVersionV1        FrameVersion = "1"
	FrameVersionV2        FrameVersion = "2"
	FrameVersionV3        FrameVersion = "3"
	FrameVersionV4        FrameVersion = "4"
	FrameVersionV5        FrameVersion = "5"
	FrameVersionV6        FrameVersion = "6"
	FrameVersionV7        FrameVersion = "7"
	FrameVersionV8        FrameVersion = "8"
	FrameVersionV9        FrameVersion = "9"
	FrameVersionV10       FrameVersion = "10"
	FrameVersionPseudoIDs FrameVersion = "org.coddy.msc4014"
)

// Event format constants.
const (
	EventFormatV1 EventFormat = iota + 1 // prev_events and auth_events as event references
	EventFormatV2                        // prev_events and auth_events as string array of event IDs
)

// Event ID format constants.
const (
	EventIDFormatV1 EventIDFormat = iota + 1 // randomised
	EventIDFormatV2                          // base64-encoded hash of event
	EventIDFormatV3                          // URL-safe base64-encoded hash of event
)

// State resolution constants.
const (
	StateResV1 StateResAlgorithm = iota + 1 // state resolution v1
	StateResV2                              // state resolution v2
)

var frameVersionMeta = map[FrameVersion]IFrameVersion{
	FrameVersionV1: FrameVersionImpl{
		ver:                                    FrameVersionV1,
		stable:                                 true,
		stateResAlgorithm:                      StateResV1,
		eventFormat:                            EventFormatV1,
		eventIDFormat:                          EventIDFormatV1,
		redactionAlgorithm:                     redactEventJSONV1,
		signatureValidityCheckFunc:             NoStrictValidityCheck,
		canonicalJSONCheck:                     noVerifyCanonicalJSON,
		notificationLevelCheck:                 noCheckLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               disallowKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV1,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV1,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV1,
	},
	FrameVersionV2: FrameVersionImpl{
		ver:                                    FrameVersionV2,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV1,
		eventIDFormat:                          EventIDFormatV1,
		redactionAlgorithm:                     redactEventJSONV1,
		signatureValidityCheckFunc:             NoStrictValidityCheck,
		canonicalJSONCheck:                     noVerifyCanonicalJSON,
		notificationLevelCheck:                 noCheckLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               disallowKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV1,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV1,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV1,
	},
	FrameVersionV3: FrameVersionImpl{
		ver:                                    FrameVersionV3,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV2,
		redactionAlgorithm:                     redactEventJSONV1,
		signatureValidityCheckFunc:             NoStrictValidityCheck,
		canonicalJSONCheck:                     noVerifyCanonicalJSON,
		notificationLevelCheck:                 noCheckLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               disallowKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV4: FrameVersionImpl{
		ver:                                    FrameVersionV4,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV1,
		signatureValidityCheckFunc:             NoStrictValidityCheck,
		canonicalJSONCheck:                     noVerifyCanonicalJSON,
		notificationLevelCheck:                 noCheckLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               disallowKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV5: FrameVersionImpl{
		ver:                                    FrameVersionV5,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV1,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     noVerifyCanonicalJSON,
		notificationLevelCheck:                 noCheckLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               disallowKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV6: FrameVersionImpl{
		ver:                                    FrameVersionV6,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV2,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               disallowKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV7: FrameVersionImpl{
		ver:                                    FrameVersionV7,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV2,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV8: FrameVersionImpl{
		ver:                                    FrameVersionV8,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV3,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           extractAuthorisedViaServerName,
		checkRestrictedJoin:                    checkRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		checkRestrictedJoinAllowedFunc:         allowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV9: FrameVersionImpl{
		ver:                                    FrameVersionV9,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV4,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           extractAuthorisedViaServerName,
		checkRestrictedJoin:                    checkRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		checkRestrictedJoinAllowedFunc:         allowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionV10: FrameVersionImpl{
		ver:                                    FrameVersionV10,
		stable:                                 true,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV4,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           extractAuthorisedViaServerName,
		checkRestrictedJoin:                    checkRestrictedJoin,
		parsePowerLevelsFunc:                   parseIntegerPowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		checkRestrictedJoinAllowedFunc:         allowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	FrameVersionPseudoIDs: FrameVersionImpl{ // currently, just a copy of V10
		ver:                                    FrameVersionPseudoIDs,
		stable:                                 false,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV4,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           extractAuthorisedViaServerName,
		checkRestrictedJoin:                    checkRestrictedJoin,
		parsePowerLevelsFunc:                   parseIntegerPowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		checkRestrictedJoinAllowedFunc:         allowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	"org.coddy.msc3667": FrameVersionImpl{ // based on frame version 7
		ver:                                    FrameVersion("org.coddy.msc3667"),
		stable:                                 false,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV2,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           emptyAuthorisedViaServerName,
		checkRestrictedJoin:                    noCheckRestrictedJoin,
		parsePowerLevelsFunc:                   parseIntegerPowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		checkRestrictedJoinAllowedFunc:         disallowRestrictedJoins,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
	"org.coddy.msc3787": FrameVersionImpl{ // roughly, the union of v7 and v9
		ver:                                    FrameVersion("org.coddy.msc3787"),
		stable:                                 false,
		stateResAlgorithm:                      StateResV2,
		eventFormat:                            EventFormatV2,
		eventIDFormat:                          EventIDFormatV3,
		redactionAlgorithm:                     redactEventJSONV4,
		signatureValidityCheckFunc:             StrictValiditySignatureCheck,
		canonicalJSONCheck:                     verifyEnforcedCanonicalJSON,
		notificationLevelCheck:                 checkNotificationLevels,
		restrictedJoinServernameFunc:           extractAuthorisedViaServerName,
		checkRestrictedJoin:                    checkRestrictedJoin,
		parsePowerLevelsFunc:                   parsePowerLevels,
		checkKnockingAllowedFunc:               checkKnocking,
		newEventFromUntrustedJSONFunc:          newEventFromUntrustedJSONV2,
		newEventFromTrustedJSONFunc:            newEventFromTrustedJSONV2,
		newEventFromTrustedJSONWithEventIDFunc: newEventFromTrustedJSONWithEventIDV2,
	},
}

// FrameVersions returns information about frame versions currently
// implemented by this commit of gocoddyserverlib.
func FrameVersions() map[FrameVersion]IFrameVersion {
	return frameVersionMeta
}

func KnownFrameVersion(verStr FrameVersion) bool {
	_, ok := frameVersionMeta[verStr]
	return ok
}

// StableFrameVersion returns true if the provided frame version
// is both known (i.e. KnownFrameVersion returns true) and marked
// as stable.
func StableFrameVersion(verStr FrameVersion) bool {
	verImpl, ok := frameVersionMeta[verStr]
	return ok && verImpl.Stable()
}

// MustGetFrameVersion is GetFrameVersion but panics if the version doesn't exist. Useful for tests.
func MustGetFrameVersion(verStr FrameVersion) IFrameVersion {
	impl, err := GetFrameVersion(verStr)
	if err != nil {
		panic(fmt.Sprintf("MustGetFrameVersion: %s", verStr))
	}
	return impl
}

func GetFrameVersion(verStr FrameVersion) (impl IFrameVersion, err error) {
	v, ok := frameVersionMeta[verStr]
	if !ok {
		return impl, UnsupportedFrameVersionError{
			Version: verStr,
		}
	}
	return v, nil
}

// StableFrameVersions returns a map of descriptions for frame
// versions that are marked as stable.
func StableFrameVersions() map[FrameVersion]IFrameVersion {
	versions := make(map[FrameVersion]IFrameVersion)
	for id, version := range FrameVersions() {
		if version.Stable() {
			versions[id] = version
		}
	}
	return versions
}

// FrameVersionDescription contains information about a frame version,
// namely whether it is marked as supported or stable in this server
// version, along with the state resolution algorithm, event ID etc
// formats used.
//
// A version is supported if the server has some support for frames
// that are this version. A version is marked as stable or unstable
// in order to hint whether the version should be used to clients
// calling the /capabilities endpoint.
// get-coddy-client-r0-capabilities
type FrameVersionImpl struct {
	ver                                    FrameVersion
	stateResAlgorithm                      StateResAlgorithm
	eventFormat                            EventFormat
	eventIDFormat                          EventIDFormat
	redactionAlgorithm                     func(eventJSON []byte) ([]byte, error)
	signatureValidityCheckFunc             SignatureValidityCheckFunc
	canonicalJSONCheck                     func(eventJSON []byte) error
	notificationLevelCheck                 func(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error
	parsePowerLevelsFunc                   func(contentBytes []byte, c *PowerLevelContent) error
	stable                                 bool
	checkRestrictedJoin                    restrictedJoinCheckFunc
	restrictedJoinServernameFunc           func(content []byte) (spec.ServerName, error)
	checkRestrictedJoinAllowedFunc         func() error
	checkKnockingAllowedFunc               func(m *membershipAllower) error
	newEventFromUntrustedJSONFunc          func(eventJSON []byte, frameVersion IFrameVersion) (result PDU, err error)
	newEventFromTrustedJSONFunc            func(eventJSON []byte, redacted bool, frameVersion IFrameVersion) (result PDU, err error)
	newEventFromTrustedJSONWithEventIDFunc func(eventID string, eventJSON []byte, redacted bool, frameVersion IFrameVersion) (result PDU, err error)
}

type restrictedJoinCheckFunc func(ctx context.Context, localServerName spec.ServerName, frameQuerier RestrictedFrameJoinQuerier, frameID spec.FrameID, senderID spec.SenderID) (string, error)

func (v FrameVersionImpl) Version() FrameVersion {
	return v.ver
}

func (v FrameVersionImpl) Stable() bool {
	return v.stable
}

// StateResAlgorithm returns the state resolution for the given frame version.
func (v FrameVersionImpl) StateResAlgorithm() StateResAlgorithm {
	return v.stateResAlgorithm
}

// EventFormat returns the event format for the given frame version.
func (v FrameVersionImpl) EventFormat() EventFormat {
	return v.eventFormat
}

// EventIDFormat returns the event ID format for the given frame version.
func (v FrameVersionImpl) EventIDFormat() EventIDFormat {
	return v.eventIDFormat
}

// SignatureValidityCheck returns true if the signature check are passing.
func (v FrameVersionImpl) SignatureValidityCheck(atTS, validUntilTS spec.Timestamp) bool {
	return v.signatureValidityCheckFunc(atTS, validUntilTS)
}

// CheckNotificationLevels checks that the changes in notification levels are allowed.
func (v FrameVersionImpl) CheckNotificationLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	return v.notificationLevelCheck(senderLevel, oldPowerLevels, newPowerLevels)
}

// CheckKnockingAllowed checks if this frame version supports knocking on frames.
func (v FrameVersionImpl) CheckKnockingAllowed(m *membershipAllower) error {
	return v.checkKnockingAllowedFunc(m)
}

// CheckRestrictedJoinsAllowed checks if this frame version allows restricted joins.
func (v FrameVersionImpl) CheckRestrictedJoinsAllowed() error {
	return v.checkRestrictedJoinAllowedFunc()
}

// RestrictedJoinServername returns the severName from a potentially existing
// join_authorised_via_users_server content field. Used to verify event signatures.
func (v FrameVersionImpl) RestrictedJoinServername(content []byte) (spec.ServerName, error) {
	return v.restrictedJoinServernameFunc(content)
}

// CheckCanonicalJSON returns an error if the eventJSON is not canonical JSON.
func (v FrameVersionImpl) CheckCanonicalJSON(eventJSON []byte) error {
	return v.canonicalJSONCheck(eventJSON)
}

// ParsePowerLevels parses the power_level directly into the passed PowerLevelContent.
func (v FrameVersionImpl) ParsePowerLevels(contentBytes []byte, c *PowerLevelContent) error {
	return v.parsePowerLevelsFunc(contentBytes, c)
}

func (v FrameVersionImpl) CheckRestrictedJoin(
	ctx context.Context,
	localServerName spec.ServerName,
	frameQuerier RestrictedFrameJoinQuerier,
	frameID spec.FrameID, senderID spec.SenderID,
) (string, error) {
	return v.checkRestrictedJoin(ctx, localServerName, frameQuerier, frameID, senderID)
}

// RedactEventJSON strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event.
func (v FrameVersionImpl) RedactEventJSON(eventJSON []byte) ([]byte, error) {
	return v.redactionAlgorithm(eventJSON)
}

func (v FrameVersionImpl) NewEventFromTrustedJSON(eventJSON []byte, redacted bool) (result PDU, err error) {
	return v.newEventFromTrustedJSONFunc(eventJSON, redacted, v)
}

func (v FrameVersionImpl) NewEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool) (result PDU, err error) {
	return v.newEventFromTrustedJSONWithEventIDFunc(eventID, eventJSON, redacted, v)
}

func (v FrameVersionImpl) NewEventFromUntrustedJSON(eventJSON []byte) (result PDU, err error) {
	return v.newEventFromUntrustedJSONFunc(eventJSON, v)
}

func (v FrameVersionImpl) NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		version: v,
	}
}
func (v FrameVersionImpl) NewEventBuilderFromProtoEvent(pe *ProtoEvent) *EventBuilder {
	eb := v.NewEventBuilder()
	// for now copies all fields, but we should be specific depending on the frame version
	eb.AuthEvents = pe.AuthEvents
	eb.Content = pe.Content
	eb.Depth = pe.Depth
	eb.PrevEvents = pe.PrevEvents
	eb.Redacts = pe.Redacts
	eb.FrameID = pe.FrameID
	eb.SenderID = pe.SenderID
	eb.Signature = pe.Signature
	eb.StateKey = pe.StateKey
	eb.Type = pe.Type
	eb.Unsigned = pe.Unsigned
	return eb
}

// NewEventFromHeaderedJSON creates a new event where the frame version is embedded in the JSON bytes.
// The version is contained in the top level "_frame_version" key.
func NewEventFromHeaderedJSON(headeredEventJSON []byte, redacted bool) (PDU, error) {
	eventID := gjson.GetBytes(headeredEventJSON, "_event_id").String()
	frameVer := FrameVersion(gjson.GetBytes(headeredEventJSON, "_frame_version").String())
	verImpl, err := GetFrameVersion(frameVer)
	if err != nil {
		return nil, err
	}
	headeredEventJSON, _ = sjson.DeleteBytes(headeredEventJSON, "_event_id")
	headeredEventJSON, _ = sjson.DeleteBytes(headeredEventJSON, "_frame_version")

	return verImpl.NewEventFromTrustedJSONWithEventID(eventID, headeredEventJSON, redacted)
}

// UnsupportedFrameVersionError occurs when a call has been made with a frame
// version that is not supported by this version of gocoddyserverlib.
type UnsupportedFrameVersionError struct {
	Version FrameVersion
}

func (e UnsupportedFrameVersionError) Error() string {
	return fmt.Sprintf("gocoddyserverlib: unsupported frame version '%s'", e.Version)
}
