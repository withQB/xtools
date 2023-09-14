package xtools

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"bytes"
	"encoding/json"
	"errors"

	"github.com/withqb/xtools/spec"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/crypto/ed25519"
)

// Event validation errors
const (
	EventValidationTooLarge int = 1
)

// EventValidationError is returned if there is a problem validating an event
type EventValidationError struct {
	Message     string
	Code        int
	Persistable bool
}

func (e EventValidationError) Error() string {
	return e.Message
}

type eventFields struct {
	FrameID         string         `json:"frame_id"`
	SenderID       string         `json:"sender"`
	Type           string         `json:"type"`
	StateKey       *string        `json:"state_key"`
	Content        spec.RawJSON   `json:"content"`
	Redacts        string         `json:"redacts"`
	Depth          int64          `json:"depth"`
	Unsigned       spec.RawJSON   `json:"unsigned,omitempty"`
	OriginServerTS spec.Timestamp `json:"origin_server_ts"`
	//Origin         spec.ServerName `json:"origin"`
}

var emptyEventReferenceList = []eventReference{}

const (
	// The event ID, frame ID, sender, event type and state key fields cannot be
	// bigger than this.
	// https://github.com/coddy-org/synapse/blob/v0.21.0/synapse/event_auth.py#L173-L182
	maxIDLength = 255
	// The entire event JSON, including signatures cannot be bigger than this.
	// https://github.com/coddy-org/synapse/blob/v0.21.0/synapse/event_auth.py#L183-184
	maxEventLength = 65536
)

func checkID(id, kind string, sigil byte) (err error) {
	if _, err = domainFromID(id); err != nil {
		return
	}
	if id[0] != sigil {
		err = fmt.Errorf(
			"gocoddyserverlib: invalid %s ID, wanted first byte to be '%c' got '%c'",
			kind, sigil, id[0],
		)
		return
	}
	if l := utf8.RuneCountInString(id); l > maxIDLength {
		err = EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gocoddyserverlib: %s ID is too long, length %d > maximum %d", kind, l, maxIDLength),
		}
		return
	}
	if l := len(id); l > maxIDLength {
		err = EventValidationError{
			Code:        EventValidationTooLarge,
			Message:     fmt.Sprintf("gocoddyserverlib: %s ID is too long, length %d bytes > maximum %d bytes", kind, l, maxIDLength),
			Persistable: true,
		}
		return
	}
	return
}

// SplitID splits a coddy ID into a local part and a server name.
func SplitID(sigil byte, id string) (local string, domain spec.ServerName, err error) {
	// IDs have the format: SIGIL LOCALPART ":" DOMAIN
	// Split on the first ":" character since the domain can contain ":"
	// characters.
	if len(id) == 0 || id[0] != sigil {
		return "", "", fmt.Errorf("gocoddyserverlib: invalid ID %q doesn't start with %q", id, sigil)
	}
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		// The ID must have a ":" character.
		return "", "", fmt.Errorf("gocoddyserverlib: invalid ID %q missing ':'", id)
	}
	return parts[0][1:], spec.ServerName(parts[1]), nil
}


type event struct {
	PrevEvents []string `json:"prev_events"`
	AuthEvents []string `json:"auth_events"`
	redacted    bool
	eventJSON   []byte
	frameVersion FrameVersion

	eventFields

	EventIDRaw string           `json:"event_id,omitempty"`
	
}

func (e *event) PrevEventIDs() []string {
	return e.PrevEvents
}

func (e *event) AuthEventIDs() []string {
	return e.AuthEvents
}

// MarshalJSON implements json.Marshaller
func (e *event) MarshalJSON() ([]byte, error) {
	if e.eventJSON == nil {
		return nil, fmt.Errorf("gocoddyserverlib: cannot serialise uninitialised Event")
	}
	return e.eventJSON, nil
}

func (e *event) SetUnsigned(unsigned interface{}) (PDU, error) {
	var eventAsMap map[string]spec.RawJSON
	var err error
	if err = json.Unmarshal(e.eventJSON, &eventAsMap); err != nil {
		return nil, err
	}
	unsignedJSON, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	eventAsMap["unsigned"] = unsignedJSON
	eventJSON, err := json.Marshal(eventAsMap)
	if err != nil {
		return nil, err
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.frameVersion); err != nil {
		return nil, err
	}
	result := *e
	result.eventJSON = eventJSON
	result.eventFields.Unsigned = unsignedJSON
	return &result, nil
}

func (e *event) SenderID() spec.SenderID {
	return spec.SenderID(e.eventFields.SenderID)
}

func (e *event) EventID() string {
	// if we already generated the eventID, don't do it again
	if e.EventIDRaw != "" {
		return e.EventIDRaw
	}
	ref, err := referenceOfEvent(e.eventJSON, e.frameVersion)
	if err != nil {
		panic(fmt.Errorf("failed to generate reference of event: %w", err))
	}
	e.EventIDRaw = ref.EventID
	return ref.EventID
}

func (e *event) Redact() {
	if e.redacted {
		return
	}
	verImpl, err := GetFrameVersion(e.frameVersion)
	if err != nil {
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v", err))
	}
	eventJSON, err := verImpl.RedactEventJSON(e.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or EventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v", err))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.frameVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or EventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v", err))
	}
	var res event
	err = json.Unmarshal(eventJSON, &res)
	if err != nil {
		panic(fmt.Errorf("gocoddyserverlib: Redact failed %v", err))
	}
	res.redacted = true
	res.eventJSON = eventJSON
	res.frameVersion = e.frameVersion
	*e = res
}

func (e *event) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU {
	eventJSON, err := signEvent(signingName, keyID, privateKey, e.eventJSON, e.frameVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or EventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.frameVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or EventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	res := &e
	(*res).eventJSON = eventJSON
	return *res
}

func newEventFromUntrustedJSON(eventJSON []byte, frameVersion IFrameVersion) (PDU, error) {
	if r := gjson.GetBytes(eventJSON, "_*"); r.Exists() {
		return nil, fmt.Errorf("gocoddyserverlib EventFromUntrustedJSON: found top-level '_' key, is this a headered event: %v", string(eventJSON))
	}
	if err := frameVersion.CheckCanonicalJSON(eventJSON); err != nil {
		return nil, BadJSONError{err}
	}

	res := &event{}
	var err error
	// Synapse removes these keys from events in case a server accidentally added them.
	// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/crypto/event_signing.py#L57-L62
	for _, key := range []string{"outlier", "destinations", "age_ts", "unsigned", "event_id"} {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, key); err != nil {
			return nil, err
		}
	}

	if err = json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}
	res.frameVersion = frameVersion.Version()

	// We know the JSON must be valid here.
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	res.eventJSON = eventJSON

	if err = checkEventContentHash(eventJSON); err != nil {
		res.redacted = true

		// If the content hash doesn't match then we have to discard all non-essential fields
		// because they've been tampered with.
		var redactedJSON []byte
		if redactedJSON, err = frameVersion.RedactEventJSON(eventJSON); err != nil {
			return nil, err
		}

		redactedJSON = CanonicalJSONAssumeValid(redactedJSON)

		// We need to ensure that `result` is the redacted event.
		// If redactedJSON is the same as eventJSON then `result` is already
		// correct. If not then we need to reparse.
		//
		// Yes, this means that for some events we parse twice (which is slow),
		// but means that parsing unredacted events is fast.
		if !bytes.Equal(redactedJSON, eventJSON) {
			result, err := frameVersion.EventFromTrustedJSON(redactedJSON, true)
			if err != nil {
				return nil, err
			}
			err = CheckFields(result)
			return result, err
		}
	}

	err = CheckFields(res)

	return res, err
}

var lenientByteLimitFrameVersions = map[FrameVersion]struct{}{

	FrameVersionV10:       {},
}

func CheckFields(input PDU) error { // nolint: gocyclo
	if input.AuthEventIDs() == nil || input.PrevEventIDs() == nil {
		return errors.New("gocoddyserverlib: auth events and prev events must not be nil")
	}
	if l := len(input.JSON()); l > maxEventLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gocoddyserverlib: event is too long, length %d bytes > maximum %d bytes", l, maxEventLength),
		}
	}

	// Compatibility to Synapse and older frames. This was always enforced by Synapse
	if l := utf8.RuneCountInString(input.Type()); l > maxIDLength {
		return EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gocoddyserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
		}
	}

	if input.StateKey() != nil {
		if l := utf8.RuneCountInString(*input.StateKey()); l > maxIDLength {
			return EventValidationError{
				Code:    EventValidationTooLarge,
				Message: fmt.Sprintf("gocoddyserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			}
		}
	}

	_, persistable := lenientByteLimitFrameVersions[input.Version()]

	// Byte size check: if these fail, then be lenient to avoid breaking frames.
	if l := len(input.Type()); l > maxIDLength {
		return EventValidationError{
			Code:        EventValidationTooLarge,
			Message:     fmt.Sprintf("gocoddyserverlib: event type is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
			Persistable: persistable,
		}
	}

	if input.StateKey() != nil {
		if l := len(*input.StateKey()); l > maxIDLength {
			return EventValidationError{
				Code:        EventValidationTooLarge,
				Message:     fmt.Sprintf("gocoddyserverlib: state key is too long, length %d bytes > maximum %d bytes", l, maxIDLength),
				Persistable: persistable,
			}
		}
	}

	if err := checkID(input.FrameID(), "frame", '!'); err != nil {
		return err
	}

	switch input.Version() {
	default:
		if err := checkID(string(input.SenderID()), "user", '@'); err != nil {
			return err
		}
	}

	return nil
}

func newEventFromTrustedJSON(eventJSON []byte, redacted bool, frameVersion IFrameVersion) (PDU, error) {
	res := event{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}
	res.frameVersion = frameVersion.Version()
	res.redacted = redacted
	res.eventJSON = eventJSON
	return &res, nil
}

func newEventFromTrustedJSONWithEventID(eventID string, eventJSON []byte, redacted bool, frameVersion IFrameVersion) (PDU, error) {
	res := &event{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}
	res.frameVersion = frameVersion.Version()
	res.eventJSON = eventJSON
	res.EventIDRaw = eventID
	res.redacted = redacted
	return res, nil
}



func (e *event) StateKey() *string {
	return e.eventFields.StateKey
}

func (e *event) StateKeyEquals(s string) bool {
	if e.eventFields.StateKey == nil {
		return false
	}
	return *e.eventFields.StateKey == s
}

func (e *event) Type() string {
	return e.eventFields.Type
}

func (e *event) Content() []byte {
	return e.eventFields.Content
}

func (e *event) JoinRule() (string, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gocoddyserverlib: JoinRule() event is not a m.frame.join_rules event, bad state key")
	}
	var content JoinRuleContent
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	return content.JoinRule, nil
}

func (e *event) HistoryVisibility() (HistoryVisibility, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gocoddyserverlib: HistoryVisibility() event is not a m.frame.history_visibility event, bad state key")
	}
	var content HistoryVisibilityContent
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	return content.HistoryVisibility, nil
}

func (e *event) Membership() (string, error) {
	var content struct {
		Membership string `json:"membership"`
	}
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	if e.StateKey() == nil {
		return "", fmt.Errorf("gocoddyserverlib: Membersip() event is not a m.frame.member event, missing state key")
	}
	return content.Membership, nil
}

func (e *event) PowerLevels() (*PowerLevelContent, error) {
	if !e.StateKeyEquals("") {
		return nil, fmt.Errorf("gocoddyserverlib: PowerLevels() event is not a m.frame.power_levels event, bad state key")
	}
	c, err := PowerLevelContentFromEvent(e)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (e *event) Version() FrameVersion {
	return e.frameVersion
}

func (e *event) FrameID() string {
	return e.eventFields.FrameID
}

func (e *event) Redacts() string {
	return e.eventFields.Redacts
}

func (e *event) Redacted() bool {
	return e.redacted
}


func (e *event) OriginServerTS() spec.Timestamp {
	return e.eventFields.OriginServerTS
}




func (e *event) Unsigned() []byte {
	return e.eventFields.Unsigned
}


func (e *event) SetUnsignedField(path string, value interface{}) error {
	// The safest way is to change the unsigned json and then reparse the
	// event fully. But since we are only changing the unsigned section,
	// which doesn't affect the signatures or hashes, we can cheat and
	// just fiddle those bits directly.

	path = "unsigned." + path
	eventJSON, err := sjson.SetBytes(e.eventJSON, path, value)
	if err != nil {
		return err
	}
	eventJSON = CanonicalJSONAssumeValid(eventJSON)

	res := gjson.GetBytes(eventJSON, "unsigned")
	unsigned := RawJSONFromResult(res, eventJSON)
	e.eventFields.Unsigned = unsigned

	e.eventJSON = eventJSON

	return nil
}


func (e *event) Depth() int64 {
	return e.eventFields.Depth
}

func (e *event) JSON() []byte {
	return e.eventJSON
}

func (e *event) ToHeaderedJSON() ([]byte, error) {
	var err error
	eventJSON := e.JSON()
	eventJSON, err = sjson.SetBytes(eventJSON, "_frame_version", e.Version())
	if err != nil {
		return []byte{}, err
	}
	eventJSON, err = sjson.SetBytes(eventJSON, "_event_id", e.EventID())
	if err != nil {
		return []byte{}, err
	}
	return eventJSON, nil
}