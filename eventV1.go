package xtools

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/withqb/xtools/spec"
	"golang.org/x/crypto/ed25519"
)

type eventV1 struct {
	redacted    bool
	eventJSON   []byte
	frameVersion FrameVersion

	eventFields

	EventIDRaw string           `json:"event_id,omitempty"`
	PrevEvents []eventReference `json:"prev_events"`
	AuthEvents []eventReference `json:"auth_events"`
}

// MarshalJSON im plements json.Marshaller
func (e eventV1) MarshalJSON() ([]byte, error) {
	if e.eventJSON == nil {
		return nil, fmt.Errorf("gocoddyserverlib: cannot serialise uninitialised Event")
	}
	return e.eventJSON, nil
}

func (e *eventV1) EventID() string {
	return e.EventIDRaw
}

func (e *eventV1) StateKey() *string {
	return e.eventFields.StateKey
}

func (e *eventV1) StateKeyEquals(s string) bool {
	if e.eventFields.StateKey == nil {
		return false
	}
	return *e.eventFields.StateKey == s
}

func (e *eventV1) Type() string {
	return e.eventFields.Type
}

func (e *eventV1) Content() []byte {
	return e.eventFields.Content
}

func (e *eventV1) JoinRule() (string, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gocoddyserverlib: JoinRule() event is not a m.frame.join_rules event, bad state key")
	}
	var content JoinRuleContent
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	return content.JoinRule, nil
}

func (e *eventV1) HistoryVisibility() (HistoryVisibility, error) {
	if !e.StateKeyEquals("") {
		return "", fmt.Errorf("gocoddyserverlib: HistoryVisibility() event is not a m.frame.history_visibility event, bad state key")
	}
	var content HistoryVisibilityContent
	if err := json.Unmarshal(e.eventFields.Content, &content); err != nil {
		return "", err
	}
	return content.HistoryVisibility, nil
}

func (e *eventV1) Membership() (string, error) {
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

func (e *eventV1) PowerLevels() (*PowerLevelContent, error) {
	if !e.StateKeyEquals("") {
		return nil, fmt.Errorf("gocoddyserverlib: PowerLevels() event is not a m.frame.power_levels event, bad state key")
	}
	c, err := NewPowerLevelContentFromEvent(e)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (e *eventV1) Version() FrameVersion {
	return e.frameVersion
}

func (e *eventV1) FrameID() string {
	return e.eventFields.FrameID
}

func (e *eventV1) Redacts() string {
	return e.eventFields.Redacts
}

func (e *eventV1) Redacted() bool {
	return e.redacted
}

func (e *eventV1) PrevEventIDs() []string {
	result := make([]string, 0, len(e.PrevEvents))
	for _, id := range e.PrevEvents {
		result = append(result, id.EventID)
	}
	return result
}

func (e *eventV1) AuthEventIDs() []string {
	result := make([]string, 0, len(e.AuthEvents))
	for _, id := range e.AuthEvents {
		result = append(result, id.EventID)
	}
	return result
}

func (e *eventV1) OriginServerTS() spec.Timestamp {
	return e.eventFields.OriginServerTS
}

func (e *eventV1) Redact() {
	if e.redacted {
		return
	}
	verImpl, err := GetFrameVersion(e.frameVersion)
	if err != nil {
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v", err))
	}
	eventJSON, err := verImpl.RedactEventJSON(e.eventJSON)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v", err))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.frameVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v", err))
	}
	var res eventV1
	err = json.Unmarshal(eventJSON, &res)
	if err != nil {
		panic(fmt.Errorf("gocoddyserverlib: populateFieldsFromJSON failed %v", err))
	}

	res.redacted = true
	res.frameVersion = e.frameVersion
	res.eventJSON = eventJSON
	*e = res
}

func (e *eventV1) SenderID() spec.SenderID {
	return spec.SenderID(e.eventFields.SenderID)
}

func (e *eventV1) Unsigned() []byte {
	return e.eventFields.Unsigned
}

func (e *eventV1) SetUnsigned(unsigned interface{}) (PDU, error) {
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

func (e *eventV1) SetUnsignedField(path string, value interface{}) error {
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

func (e *eventV1) Sign(signingName string, keyID KeyID, privateKey ed25519.PrivateKey) PDU {
	eventJSON, err := signEvent(signingName, keyID, privateKey, e.eventJSON, e.frameVersion)
	if err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	if eventJSON, err = EnforcedCanonicalJSON(eventJSON, e.frameVersion); err != nil {
		// This is unreachable for events created with EventBuilder.Build or NewEventFromUntrustedJSON
		panic(fmt.Errorf("gocoddyserverlib: invalid event %v (%q)", err, string(e.eventJSON)))
	}
	res := &e
	(*res).eventJSON = eventJSON
	return *res
}

func (e *eventV1) Depth() int64 {
	return e.eventFields.Depth
}

func (e *eventV1) JSON() []byte {
	return e.eventJSON
}

func (e *eventV1) ToHeaderedJSON() ([]byte, error) {
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

func newEventFromUntrustedJSONV1(eventJSON []byte, frameVersion IFrameVersion) (PDU, error) {
	if r := gjson.GetBytes(eventJSON, "_*"); r.Exists() {
		return nil, fmt.Errorf("gocoddyserverlib NewEventFromUntrustedJSON: found top-level '_' key, is this a headered event: %v", string(eventJSON))
	}
	if err := frameVersion.CheckCanonicalJSON(eventJSON); err != nil {
		return nil, BadJSONError{err}
	}

	res := &eventV1{}
	res.frameVersion = frameVersion.Version()

	// Synapse removes these keys from events in case a server accidentally added them.
	// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/crypto/event_signing.py#L57-L62
	var err error
	for _, key := range []string{"outlier", "destinations", "age_ts", "unsigned"} {
		if eventJSON, err = sjson.DeleteBytes(eventJSON, key); err != nil {
			return nil, err
		}
	}

	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}

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
			result, err := frameVersion.NewEventFromTrustedJSON(redactedJSON, true)
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

func newEventFromTrustedJSONV1(eventJSON []byte, redacted bool, frameVersion IFrameVersion) (PDU, error) {
	res := &eventV1{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}
	res.eventJSON = eventJSON
	res.frameVersion = frameVersion.Version()
	res.redacted = redacted
	return res, nil
}

func newEventFromTrustedJSONWithEventIDV1(eventID string, eventJSON []byte, redacted bool, frameVersion IFrameVersion) (PDU, error) {
	res := &eventV1{}
	if err := json.Unmarshal(eventJSON, &res); err != nil {
		return nil, err
	}
	res.EventIDRaw = eventID
	res.eventJSON = eventJSON
	res.frameVersion = frameVersion.Version()
	res.redacted = redacted
	return res, nil
}
