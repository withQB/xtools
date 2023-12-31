package xtools

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/withqb/xtools/spec"
	"golang.org/x/crypto/ed25519"
)

// CreateContent is the JSON content of a m.frame.create event along with
// the top level keys needed for auth.
type CreateContent struct {
	// We need the domain of the create event when checking federatability.
	senderDomain string
	// We need the frameID to check that events are in the same frame as the create event.
	frameID string
	// We need the eventID to check the first join event in the frame.
	eventID string
	// The "m.federate" flag tells us whether the frame can be federated to other servers.
	Federate *bool `json:"m.federate,omitempty"`
	// The creator of the frame tells us what the default power levels are.
	Creator string `json:"creator"`
	// The version of the frame. Should be treated as "1" when the key doesn't exist.
	FrameVersion *FrameVersion `json:"frame_version,omitempty"`
	// The predecessor of the frame.
	Predecessor *PreviousFrame `json:"predecessor,omitempty"`
	// The frame type.
	FrameType string `json:"type,omitempty"`
}

// PreviousFrame is the "Previous Frame" structure defined
type PreviousFrame struct {
	FrameID  string `json:"frame_id"`
	EventID string `json:"event_id"`
}

// CreateContentFromAuthEvents loads the create event content from the create event in the
// auth events.
func CreateContentFromAuthEvents(authEvents AuthEventProvider, userIDForSender spec.UserIDForSender) (c CreateContent, err error) {
	var createEvent PDU
	if createEvent, err = authEvents.Create(); err != nil {
		return
	}
	if createEvent == nil {
		err = errorf("missing create event")
		return
	}
	if err = json.Unmarshal(createEvent.Content(), &c); err != nil {
		err = errorf("unparseable create event content: %s", err.Error())
		return
	}
	c.frameID = createEvent.FrameID()
	c.eventID = createEvent.EventID()
	validFrameID, err := spec.NewFrameID(createEvent.FrameID())
	if err != nil {
		err = errorf("frameID is invalid: %s", err.Error())
		return
	}
	sender, err := userIDForSender(*validFrameID, createEvent.SenderID())
	if err != nil {
		err = errorf("invalid sender userID: %s", err.Error())
		return
	}
	c.senderDomain = string(sender.Domain())
	return
}

// DomainAllowed checks whether the domain is allowed in the frame by the
// "m.federate" flag.
func (c *CreateContent) DomainAllowed(domain string) error {
	if domain == c.senderDomain {
		// If the domain matches the domain of the create event then the event
		// is always allowed regardless of the value of the "m.federate" flag.
		return nil
	}
	if c.Federate == nil || *c.Federate {
		// The m.federate field defaults to true.
		// If the domains are different then event is only allowed if the
		// "m.federate" flag is absent or true.
		return nil
	}
	return errorf("frame is unfederatable")
}

// UserIDAllowed checks whether the domain part of the user ID is allowed in
// the frame by the "m.federate" flag.
func (c *CreateContent) UserIDAllowed(id spec.UserID) error {
	return c.DomainAllowed(string(id.Domain()))
}

// domainFromID returns everything after the first ":" character to extract
// the domain part of a coddy ID.
func domainFromID(id string) (string, error) {
	// IDs have the format: SIGIL LOCALPART ":" DOMAIN
	// Split on the first ":" character since the domain can contain ":"
	// characters.
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		// The ID must have a ":" character.
		return "", errorf("invalid ID: %q", id)
	}
	// Return everything after the first ":" character.
	return parts[1], nil
}

// MemberContent is the JSON content of a m.frame.member event needed for auth checks.
// See m-frame-member for descriptions of the fields.
type MemberContent struct {
	// We use the membership key in order to check if the user is in the frame.
	Membership  string `json:"membership"`
	DisplayName string `json:"displayname,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	Reason      string `json:"reason,omitempty"`
	IsDirect    bool   `json:"is_direct,omitempty"`
	// We use the third_party_invite key to special case thirdparty invites.
	ThirdPartyInvite *MemberThirdPartyInvite `json:"third_party_invite,omitempty"`
	// Restricted join rules require a user with invite permission to be nominated,
	// so that their membership can be included in the auth events.
	AuthorisedVia string `json:"join_authorised_via_users_server,omitempty"`

	// The MXIDMapping used in pseudo ID frames
	MXIDMapping *MXIDMapping `json:"mxid_mapping,omitempty"`
}

type MXIDMapping struct {
	UserFrameKey spec.SenderID                                  `json:"user_frame_key"`
	UserID      string                                         `json:"user_id"`
	Signatures  map[spec.ServerName]map[KeyID]spec.Base64Bytes `json:"signatures,omitempty"`
}

// Sign signs the MXIDMapping with the signing key of the server.
// Sets the Signatures field on success.
func (m *MXIDMapping) Sign(serverName spec.ServerName, keyID KeyID, privateKey ed25519.PrivateKey) error {
	m.Signatures = nil // ensure we don't marshal/sign existing signatures
	unsorted, err := json.Marshal(m)
	if err != nil {
		return err
	}

	canonical, err := CanonicalJSON(unsorted)
	if err != nil {
		return err
	}

	signature := spec.Base64Bytes(ed25519.Sign(privateKey, canonical))
	if m.Signatures == nil {
		m.Signatures = make(map[spec.ServerName]map[KeyID]spec.Base64Bytes)
	}
	if m.Signatures[serverName] == nil {
		m.Signatures[serverName] = make(map[KeyID]spec.Base64Bytes)
	}
	m.Signatures[serverName][keyID] = signature
	return nil
}

// MemberThirdPartyInvite is the "Invite" structure defined at m-frame-member
type MemberThirdPartyInvite struct {
	DisplayName string                       `json:"display_name"`
	Signed      MemberThirdPartyInviteSigned `json:"signed"`
}

// MemberThirdPartyInviteSigned is the "signed" structure defined at m-frame-member
type MemberThirdPartyInviteSigned struct {
	MXID       string                       `json:"mxid"`
	Signatures map[string]map[string]string `json:"signatures"`
	Token      string                       `json:"token"`
}

// MemberContentFromAuthEvents loads the member content from the member event for the senderID in the auth events.
// Returns an error if there was an error loading the member event or parsing the event content.
func MemberContentFromAuthEvents(authEvents AuthEventProvider, senderID spec.SenderID) (c MemberContent, err error) {
	var memberEvent PDU
	if memberEvent, err = authEvents.Member(senderID); err != nil {
		return
	}
	if memberEvent == nil {
		// If there isn't a member event then the membership for the user
		// defaults to leave.
		c.Membership = spec.Leave
		return
	}
	return MemberContentFromEvent(memberEvent)
}

// MemberContentFromEvent parse the member content from an event.
// Returns an error if the content couldn't be parsed.
func MemberContentFromEvent(event PDU) (c MemberContent, err error) {
	if err = json.Unmarshal(event.Content(), &c); err != nil {
		var partial membershipContent
		if err = json.Unmarshal(event.Content(), &partial); err != nil {
			err = errorf("unparseable member event content: %s", err.Error())
			return
		}
		c.Membership = partial.Membership
		c.ThirdPartyInvite = partial.ThirdPartyInvite
		c.AuthorisedVia = partial.AuthorizedVia
	}
	return
}

// ThirdPartyInviteContent is the JSON content of a m.frame.third_party_invite event needed for auth checks.
// See m-frame-third-party-invite for descriptions of the fields.
type ThirdPartyInviteContent struct {
	DisplayName    string `json:"display_name"`
	KeyValidityURL string `json:"key_validity_url"`
	PublicKey      string `json:"public_key"`
	// Public keys are used to verify the signature of a m.frame.member event that
	// came from a m.frame.third_party_invite event
	PublicKeys []PublicKey `json:"public_keys"`
}

// PublicKey is the "PublicKeys" structure defined
type PublicKey struct {
	PublicKey      spec.Base64Bytes `json:"public_key"`
	KeyValidityURL string           `json:"key_validity_url"`
}

// ThirdPartyInviteContentFromAuthEvents loads the third party invite content from the third party invite event for the state key (token) in the auth events.
// Returns an error if there was an error loading the third party invite event or parsing the event content.
func ThirdPartyInviteContentFromAuthEvents(authEvents AuthEventProvider, token string) (t ThirdPartyInviteContent, err error) {
	var thirdPartyInviteEvent PDU
	if thirdPartyInviteEvent, err = authEvents.ThirdPartyInvite(token); err != nil {
		return
	}
	if thirdPartyInviteEvent == nil {
		// If there isn't a third_party_invite event, then we return with an error
		err = errorf("Couldn't find third party invite event")
		return
	}
	if err = json.Unmarshal(thirdPartyInviteEvent.Content(), &t); err != nil {
		err = errorf("unparseable third party invite event content: %s", err.Error())
	}
	return
}

// HistoryVisibilityContent is the JSON content of a m.frame.history_visibility event.
// See frame-history-visibility for descriptions of the fields.
type HistoryVisibilityContent struct {
	HistoryVisibility HistoryVisibility `json:"history_visibility"`
}

type HistoryVisibility string

const (
	HistoryVisibilityWorldReadable HistoryVisibility = "world_readable"
	HistoryVisibilityShared        HistoryVisibility = "shared"
	HistoryVisibilityInvited       HistoryVisibility = "invited"
	HistoryVisibilityJoined        HistoryVisibility = "joined"
)

// Scan implements sql.Scanner
func (h *HistoryVisibility) Scan(src interface{}) error {
	switch v := src.(type) {
	case int64:
		s, ok := hisVisIntToStringMapping[uint8(v)]
		if !ok { // history visibility is unknown, default to shared
			*h = HistoryVisibilityShared
			return nil
		}
		*h = s
		return nil
	case float64:
		s, ok := hisVisIntToStringMapping[uint8(v)]
		if !ok { // history visibility is unknown, default to shared
			*h = HistoryVisibilityShared
			return nil
		}
		*h = s
		return nil
	default:
		return fmt.Errorf("unknown source type: %T for HistoryVisibilty", src)
	}
}

// Value implements sql.Valuer
func (h HistoryVisibility) Value() (driver.Value, error) {
	v, ok := hisVisStringToIntMapping[h]
	if !ok {
		return int64(hisVisStringToIntMapping[HistoryVisibilityShared]), nil
	}
	return int64(v), nil
}

var hisVisStringToIntMapping = map[HistoryVisibility]uint8{
	HistoryVisibilityWorldReadable: 1, // Starting at 1, to avoid confusions with Go default values
	HistoryVisibilityShared:        2,
	HistoryVisibilityInvited:       3,
	HistoryVisibilityJoined:        4,
}

var hisVisIntToStringMapping = map[uint8]HistoryVisibility{
	1: HistoryVisibilityWorldReadable, // Starting at 1, to avoid confusions with Go default values
	2: HistoryVisibilityShared,
	3: HistoryVisibilityInvited,
	4: HistoryVisibilityJoined,
}

// JoinRuleContent is the JSON content of a m.frame.join_rules event needed for auth checks.
// See  m-frame-join-rules for descriptions of the fields.
type JoinRuleContent struct {
	// We use the join_rule key to check whether join m.frame.member events are allowed.
	JoinRule string                     `json:"join_rule"`
	Allow    []JoinRuleContentAllowRule `json:"allow,omitempty"`
}

type JoinRuleContentAllowRule struct {
	Type   string `json:"type"`
	FrameID string `json:"frame_id"`
}

// JoinRuleContentFromAuthEvents loads the join rule content from the join rules event in the auth event.
// Returns an error if there was an error loading the join rule event or parsing the content.
func JoinRuleContentFromAuthEvents(authEvents AuthEventProvider) (c JoinRuleContent, err error) {
	// Start off with "invite" as the default. Hopefully the unmarshal
	// step later will replace it with a better value.
	c.JoinRule = spec.Invite
	// Then see if the specified join event contains something better.
	joinRulesEvent, err := authEvents.JoinRules()
	if err != nil {
		return
	}
	if joinRulesEvent == nil {
		return
	}
	if err = json.Unmarshal(joinRulesEvent.Content(), &c); err != nil {
		err = errorf("unparseable join_rules event content: %s", err.Error())
		return
	}
	return
}

// PowerLevelContent is the JSON content of a m.frame.power_levels event needed for auth checks.
// Typically the user calls PowerLevelContentFromAuthEvents instead of
// unmarshalling the content directly from JSON so defaults can be applied.
// However, the JSON key names are still preserved so it's possible to marshal
// the struct into JSON easily.
// See m-frame-power-levels for descriptions of the fields.
type PowerLevelContent struct {
	Ban           int64            `json:"ban"`
	Invite        int64            `json:"invite"`
	Kick          int64            `json:"kick"`
	Redact        int64            `json:"redact"`
	Users         map[string]int64 `json:"users"`
	UsersDefault  int64            `json:"users_default"`
	Events        map[string]int64 `json:"events"`
	EventsDefault int64            `json:"events_default"`
	StateDefault  int64            `json:"state_default"`
	Notifications map[string]int64 `json:"notifications"`
}

// UserLevel returns the power level a user has in the frame.
func (c *PowerLevelContent) UserLevel(senderID spec.SenderID) int64 {
	level, ok := c.Users[string(senderID)]
	if ok {
		return level
	}
	return c.UsersDefault
}

// EventLevel returns the power level needed to send an event in the frame.
func (c *PowerLevelContent) EventLevel(eventType string, isState bool) int64 {
	if eventType == spec.MFrameThirdPartyInvite {
		// Special case third_party_invite events to have the same level as
		// m.frame.member invite events.
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L182
		return c.Invite
	}
	level, ok := c.Events[eventType]
	if ok {
		return level
	}
	if isState {
		return c.StateDefault
	}
	return c.EventsDefault
}

// UserLevel returns the power level a user has in the frame.
func (c *PowerLevelContent) NotificationLevel(notification string) int64 {
	level, ok := c.Notifications[notification]
	if ok {
		return level
	}
	// frame	integer	The level required to trigger an @frame notification. Defaults to 50 if unspecified.
	return 50
}

// PowerLevelContentFromAuthEvents loads the power level content from the
// power level event in the auth events or returns the default values if there
// is no power level event.
func PowerLevelContentFromAuthEvents(authEvents AuthEventProvider, creatorUserID string) (c PowerLevelContent, err error) {
	powerLevelsEvent, err := authEvents.PowerLevels()
	if err != nil {
		return
	}
	if powerLevelsEvent != nil {
		return PowerLevelContentFromEvent(powerLevelsEvent)
	}

	// If there are no power levels then fall back to defaults.
	c.Defaults()
	// If there is no power level event then the creator gets level 100
	// If we want users to be able to set PLs > 100 with power_level_content_override
	// then we need to set the upper bound: maximum allowable JSON value is (2^53)-1.
	c.Users = map[string]int64{creatorUserID: 9007199254740991}
	// If there is no power level event then the state_default is level 50
	// https://github.com/coddy-org/synapse/blob/v1.38.0/synapse/event_auth.py#L437
	// Previously it was 0, but this was changed in:
	// https://github.com/coddy-org/synapse/commit/5c9afd6f80cf04367fe9b02c396af9f85e02a611
	c.StateDefault = 50
	return
}

// Defaults sets the power levels to their default values.
func (c *PowerLevelContent) Defaults() {
	c.Invite = 50
	c.Ban = 50
	c.Kick = 50
	c.Redact = 50
	c.UsersDefault = 0
	c.EventsDefault = 0
	c.StateDefault = 50
	c.Notifications = map[string]int64{
		"frame": 50,
	}
}

// PowerLevelContentFromEvent loads the power level content from an event.
func PowerLevelContentFromEvent(event PDU) (c PowerLevelContent, err error) {
	// Set the levels to their default values.
	c.Defaults()

	verImpl, err := GetFrameVersion(event.Version())
	if err != nil {
		return c, err
	}

	if err = verImpl.ParsePowerLevels(event.Content(), &c); err != nil {
		err = errorf("unparseable power_levels event content: %s", err.Error())
		return
	}
	return
}

// parseIntegerPowerLevels unmarshals directly to PowerLevelContent, since that will kick up an
// error if one of the power levels isn't an int64.
func parseIntegerPowerLevels(contentBytes []byte, c *PowerLevelContent) error {
	return json.Unmarshal(contentBytes, c)
}

// Check if the user ID is a valid user ID.
func isValidUserID(userID string) bool {
	// TDO: Do we want to add anymore checks beyond checking the sigil and that it has a domain part?
	return userID[0] == '@' && strings.IndexByte(userID, ':') != -1
}

type RelationContent struct {
	Relations *RelatesTo `json:"m.relates_to"`
}

type RelatesTo struct {
	EventID      string `json:"event_id"`
	RelationType string `json:"rel_type"`
}
