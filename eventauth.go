package xtools

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/withqb/xtools/spec"
	"github.com/withqb/xutil"
)

// StateNeeded lists the event types and state_keys needed to authenticate an event.
type StateNeeded struct {
	// Is the m.frame.create event needed to auth the event.
	Create bool
	// Is the m.frame.join_rules event needed to auth the event.
	JoinRules bool
	// Is the m.frame.power_levels event needed to auth the event.
	PowerLevels bool
	// List of m.frame.member state_keys needed to auth the event
	Member []string
	// List of m.frame.third_party_invite state_keys
	ThirdPartyInvite []string
}

// Tuples returns the needed state key tuples for performing auth on an event.
func (s StateNeeded) Tuples() (res []StateKeyTuple) {
	if s.Create {
		res = append(res, StateKeyTuple{spec.MFrameCreate, ""})
	}
	if s.JoinRules {
		res = append(res, StateKeyTuple{spec.MFrameJoinRules, ""})
	}
	if s.PowerLevels {
		res = append(res, StateKeyTuple{spec.MFramePowerLevels, ""})
	}
	for _, senderID := range s.Member {
		res = append(res, StateKeyTuple{spec.MFrameMember, senderID})
	}
	for _, token := range s.ThirdPartyInvite {
		res = append(res, StateKeyTuple{spec.MFrameThirdPartyInvite, token})
	}
	return
}

// AuthEventReferences returns the auth_events references for the StateNeeded. Returns an error if the
// provider returns an error. If an event is missing from the provider but is required in StateNeeded, it
// is skipped over: no error is returned.
func (s StateNeeded) AuthEventReferences(provider AuthEventProvider) (refs []string, err error) { // nolint: gocyclo
	refs = make([]string, 0, 5) // we'll probably have about ~5 events, so pre allocate that
	var e PDU
	if s.Create {
		if e, err = provider.Create(); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventID())
		}
	}
	if s.JoinRules {
		if e, err = provider.JoinRules(); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventID())
		}
	}
	if s.PowerLevels {
		if e, err = provider.PowerLevels(); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventID())
		}
	}
	for _, userID := range s.Member {
		if e, err = provider.Member(spec.SenderID(userID)); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventID())
		}
	}
	for _, token := range s.ThirdPartyInvite {
		if e, err = provider.ThirdPartyInvite(token); err != nil {
			return
		} else if e != nil {
			refs = append(refs, e.EventID())
		}
	}
	return
}

// The minimum amount of information we need to accumulate state for a membership event.
type membershipContent struct {
	Membership string `json:"membership"`
	// We use the third_party_invite key to special case thirdparty invites.
	ThirdPartyInvite *MemberThirdPartyInvite `json:"third_party_invite,omitempty"`
	// The user that authorised the join, in the case that the restricted join
	// rule is in effect.
	AuthorizedVia string `json:"join_authorised_via_users_server,omitempty"`
}

// StateNeededForProtoEvent returns the event types and state_keys needed to authenticate the
// event being built. These events should be put under 'auth_events' for the event being built.
// Returns an error if the state needed could not be calculated with the given builder, e.g
// if there is a m.frame.member without a membership key.
func StateNeededForProtoEvent(protoEvent *ProtoEvent) (result StateNeeded, err error) {
	// Extract the 'content' object from the event if it is m.frame.member as we need to know 'membership'
	var content *membershipContent
	if protoEvent.Type == spec.MFrameMember {
		if err = json.Unmarshal(protoEvent.Content, &content); err != nil {
			err = errorf("unparseable member event content: %s", err.Error())
			return
		}
	}
	err = accumulateStateNeeded(&result, protoEvent.Type, spec.SenderID(protoEvent.SenderID), protoEvent.StateKey, content)
	result.Member = xutil.UniqueStrings(result.Member)
	result.ThirdPartyInvite = xutil.UniqueStrings(result.ThirdPartyInvite)
	return
}

// StateNeededForAuth returns the event types and state_keys needed to authenticate an event.
// This takes a list of events to facilitate bulk processing when doing auth checks as part of state conflict resolution.
func StateNeededForAuth(events []PDU) (result StateNeeded) {
	for _, event := range events {
		// Extract the 'content' object from the event if it is m.frame.member as we need to know 'membership'
		var content *membershipContent
		if event.Type() == spec.MFrameMember {
			_ = json.Unmarshal(event.Content(), &content)
		}
		// Ignore errors when accumulating state needed.
		// The event will be rejected when the actual checks encounter the same error.
		_ = accumulateStateNeeded(&result, event.Type(), event.SenderID(), event.StateKey(), content)
	}

	// Deduplicate the state keys.
	result.Member = xutil.UniqueStrings(result.Member)
	result.ThirdPartyInvite = xutil.UniqueStrings(result.ThirdPartyInvite)
	return
}

func accumulateStateNeeded(result *StateNeeded, eventType string, sender spec.SenderID, stateKey *string, content *membershipContent) (err error) {
	switch eventType {
	case spec.MFrameCreate:
		// The create event doesn't require any state to authenticate.
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L123
	case spec.MFrameAliases:
		// Alias events need:
		//  * The create event.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L128
		// Alias events need no further authentication.
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L160
		result.Create = true
	case spec.MFrameMember:
		// Member events need:
		//  * The previous membership of the target.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L355
		//  * The current membership state of the sender.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L348
		//  * The join rules for the frame if the event is a join event.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L361
		//  * The power levels for the frame.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L370
		//  * And optionally may require a m.third_party_invite event
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L393
		//  * If using a restricted join rule, we should also include the membership event
		//    of the user nominated in the `join_authorised_via_users_server` key
		//    https://github.com/coddy-org/coddy-doc/blob/clokep/restricted-frames/proposals/3083-restricted-frames.md
		if content == nil {
			err = errorf("missing memberContent for m.frame.member event")
			return
		}
		result.Create = true
		result.PowerLevels = true
		result.Member = append(result.Member, string(sender))
		if stateKey != nil {
			result.Member = append(result.Member, *stateKey)
		}
		if content.Membership == spec.Join || content.Membership == spec.Knock || content.Membership == spec.Invite {
			result.JoinRules = true
		}
		if content.ThirdPartyInvite != nil {
			token, tokErr := thirdPartyInviteToken(content.ThirdPartyInvite)
			if tokErr != nil {
				err = errorf("could not get third-party token: %s", tokErr)
				return
			}
			result.ThirdPartyInvite = append(result.ThirdPartyInvite, token)
		}
		if content.AuthorizedVia != "" {
			result.Member = append(result.Member, content.AuthorizedVia)
		}
	default:
		// All other events need:
		//  * The membership of the sender.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L177
		//  * The power levels for the frame.
		//    https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L196
		result.Create = true
		result.PowerLevels = true
		result.Member = append(result.Member, string(sender))
	}
	return
}

// thirdPartyInviteToken extracts the token from the third_party_invite.
func thirdPartyInviteToken(thirdPartyInvite *MemberThirdPartyInvite) (string, error) {
	if thirdPartyInvite.Signed.Token == "" {
		return "", fmt.Errorf("missing 'third_party_invite.signed.token' JSON key")
	}
	return thirdPartyInvite.Signed.Token, nil
}

// AuthEventProvider provides auth_events for the authentication checks.
type AuthEventProvider interface {
	// Create returns the m.frame.create event for the frame or nil if there isn't a m.frame.create event.
	Create() (PDU, error)
	// JoinRules returns the m.frame.join_rules event for the frame or nil if there isn't a m.frame.join_rules event.
	JoinRules() (PDU, error)
	// PowerLevels returns the m.frame.power_levels event for the frame or nil if there isn't a m.frame.power_levels event.
	PowerLevels() (PDU, error)
	// Member returns the m.frame.member event for the given senderID state_key or nil if there isn't a m.frame.member event.
	Member(stateKey spec.SenderID) (PDU, error)
	// ThirdPartyInvite returns the m.frame.third_party_invite event for the
	// given state_key or nil if there isn't a m.frame.third_party_invite event
	ThirdPartyInvite(stateKey string) (PDU, error)
	// Valid verifies that all auth events are from the same frame.
	Valid() bool
}

// AuthEvents is an implementation of AuthEventProvider backed by a map.
type AuthEvents struct {
	events  map[StateKeyTuple]PDU
	frameIDs map[string]struct{}
}

// Valid verifies that all auth events are from the same frame.
func (a *AuthEvents) Valid() bool {
	return len(a.frameIDs) <= 1
}

// AddEvent adds an event to the provider. If an event already existed for the (type, state_key) then
// the event is replaced with the new event. Only returns an error if the event is not a state event.
func (a *AuthEvents) AddEvent(event PDU) error {
	if event.StateKey() == nil {
		return fmt.Errorf("AddEvent: event %q does not have a state key", event.Type())
	}
	a.frameIDs[event.FrameID()] = struct{}{}
	a.events[StateKeyTuple{event.Type(), *event.StateKey()}] = event
	return nil
}

// Create implements AuthEventProvider
func (a *AuthEvents) Create() (PDU, error) {
	return a.events[StateKeyTuple{spec.MFrameCreate, ""}], nil
}

// JoinRules implements AuthEventProvider
func (a *AuthEvents) JoinRules() (PDU, error) {
	return a.events[StateKeyTuple{spec.MFrameJoinRules, ""}], nil
}

// PowerLevels implements AuthEventProvider
func (a *AuthEvents) PowerLevels() (PDU, error) {
	return a.events[StateKeyTuple{spec.MFramePowerLevels, ""}], nil
}

// Member implements AuthEventProvider
func (a *AuthEvents) Member(stateKey spec.SenderID) (PDU, error) {
	return a.events[StateKeyTuple{spec.MFrameMember, string(stateKey)}], nil
}

// ThirdPartyInvite implements AuthEventProvider
func (a *AuthEvents) ThirdPartyInvite(stateKey string) (PDU, error) {
	return a.events[StateKeyTuple{spec.MFrameThirdPartyInvite, stateKey}], nil
}

// Clear removes all entries from the AuthEventProvider.
func (a *AuthEvents) Clear() {
	for k := range a.events {
		delete(a.events, k)
	}
}

// NewAuthEvents returns an AuthEventProvider backed by the given events. New events can be added by
// calling AddEvent().
func NewAuthEvents(events []PDU) AuthEvents {
	a := AuthEvents{
		events:  make(map[StateKeyTuple]PDU, len(events)),
		frameIDs: make(map[string]struct{}),
	}
	for _, e := range events {
		a.AddEvent(e) // nolint: errcheck
	}
	return a
}

// A NotAllowed error is returned if an event does not pass the auth checks.
type NotAllowed struct {
	Message string
}

func (a *NotAllowed) Error() string {
	return "eventauth: " + a.Message
}

func errorf(message string, args ...interface{}) error {
	return &NotAllowed{Message: fmt.Sprintf(message, args...)}
}

// allowerContext allows auth checks to be run using cached create,
// power level and join rule events. This can help when authing a large
// state set for a specific frame.
type allowerContext struct {
	// The auth event provider. This must be set.
	provider AuthEventProvider

	// Provides the current UserID for a given SenderID.
	userIDQuerier spec.UserIDForSender

	// Event references used to see when we need to update.
	createEvent      PDU // The m.frame.create event for the frame.
	powerLevelsEvent PDU // The m.frame.power_levels event for the frame.
	joinRuleEvent    PDU // The m.frame.join_rules event for the frame.

	// Event contents used for quick lookup.
	create      CreateContent     // The m.frame.create content for the frame.
	powerLevels PowerLevelContent // The m.frame.power_levels content for the frame.
	joinRule    JoinRuleContent   // The m.frame.join_rules content for the frame.

	frameID spec.FrameID
}

func newAllowerContext(provider AuthEventProvider, userIDQuerier spec.UserIDForSender, frameID spec.FrameID) *allowerContext {
	a := &allowerContext{
		userIDQuerier: userIDQuerier,
		frameID:        frameID,
	}
	a.update(provider)
	return a
}

// update updates the auth event provider with new event contents.
// It will wipe the state if a new provider is given. If the same provider
// is given then it will only unmarshal event contents if the provided events
// have changed, to reduce allocations in state resolution.
func (a *allowerContext) update(provider AuthEventProvider) {
	if provider != a.provider {
		a.provider = provider
		a.createEvent, a.powerLevelsEvent, a.joinRuleEvent = nil, nil, nil
	}
	if e, _ := provider.Create(); a.createEvent == nil || a.createEvent != e {
		if c, err := CreateContentFromAuthEvents(provider, a.userIDQuerier); err == nil {
			a.createEvent = e
			a.create = c
		}
	}
	if e, _ := provider.PowerLevels(); a.powerLevelsEvent == nil || a.powerLevelsEvent != e {
		if p, err := PowerLevelContentFromAuthEvents(provider, a.create.Creator); err == nil {
			a.powerLevelsEvent = e
			a.powerLevels = p
		}
	}
	if e, _ := provider.JoinRules(); a.joinRuleEvent == nil || a.joinRuleEvent != e {
		if j, err := JoinRuleContentFromAuthEvents(provider); err == nil {
			a.joinRuleEvent, _ = provider.JoinRules()
			a.joinRule = j
		}
	}
}

// Allowed checks whether an event is allowed by the auth events, using the
// create, power level and join events from the allowerContext. This is a
// quick path designed to speed up state resolution.
// It returns a NotAllowed error if the event is not allowed.
// If there was an error loading the auth events then it returns that error.
func (a *allowerContext) allowed(event PDU) error {
	switch event.Type() {
	case spec.MFrameCreate:
		return a.createEventAllowed(event)
	case spec.MFrameAliases:
		return a.aliasEventAllowed(event)
	case spec.MFrameMember:
		return a.memberEventAllowed(event)
	case spec.MFramePowerLevels:
		return a.powerLevelsEventAllowed(event)
	case spec.MFrameRedaction:
		return a.redactEventAllowed(event)
	default:
		return a.defaultEventAllowed(event)
	}
}

// Allowed checks whether an event is allowed by the auth events.
// It returns a NotAllowed error if the event is not allowed.
// If there was an error loading the auth events then it returns that error.
func Allowed(event PDU, authEvents AuthEventProvider, userIDQuerier spec.UserIDForSender) error {
	if !authEvents.Valid() {
		return errorf("authEvents contains events from different frames")
	}
	validFrameID, err := spec.NewFrameID(event.FrameID())
	if err != nil {
		return err
	}
	return newAllowerContext(authEvents, userIDQuerier, *validFrameID).allowed(event)
}

// createEventAllowed checks whether the m.frame.create event is allowed.
// It returns an error if the event is not allowed.
func (a *allowerContext) createEventAllowed(event PDU) error {
	if !event.StateKeyEquals("") {
		return errorf("create event state key is not empty: %v", event.StateKey())
	}
	if len(event.PrevEventIDs()) > 0 {
		return errorf("create event must be the first event in the frame: found %d prev_events", len(event.PrevEventIDs()))
	}
	frameIDDomain, err := domainFromID(event.FrameID())
	if err != nil {
		return err
	}
	sender, err := a.userIDQuerier(a.frameID, event.SenderID())
	if err != nil {
		return err
	}
	if string(sender.Domain()) != frameIDDomain {
		return errorf("create event frame ID domain does not match sender: %q != %q", frameIDDomain, sender.String())
	}
	c := struct {
		Creator     *string      `json:"creator"`
		FrameVersion *FrameVersion `json:"frame_version"`
	}{}
	if err := json.Unmarshal(event.Content(), &c); err != nil {
		return errorf("create event has invalid content: %s", err.Error())
	}
	if c.Creator == nil {
		return errorf("create event has no creator field")
	}
	if c.FrameVersion != nil {
		if !KnownFrameVersion(*c.FrameVersion) {
			return errorf("create event has unrecognised frame version %q", *c.FrameVersion)
		}
	}
	return nil
}

// memberEventAllowed checks whether the m.frame.member event is allowed.
// Membership events have different authentication rules to ordinary events.
func (a *allowerContext) memberEventAllowed(event PDU) error {
	allower, err := a.newMembershipAllower(a.provider, event)
	if err != nil {
		return err
	}
	return allower.membershipAllowed(event)
}

// aliasEventAllowed checks whether the m.frame.aliases event is allowed.
// Alias events have different authentication rules to ordinary events.
func (a *allowerContext) aliasEventAllowed(event PDU) error {
	// The alias events have different auth rules to ordinary events.
	// In particular we allow any server to send a m.frame.aliases event without checking if the sender is in the frame.
	// This allows server admins to update the m.frame.aliases event for their server when they change the aliases on their server.
	// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L143-L160
	sender, err := a.userIDQuerier(a.frameID, event.SenderID())
	if err != nil {
		return err
	}

	if event.FrameID() != a.create.frameID {
		return errorf(
			"create event has different frameID: %q (%s) != %q (%s)",
			event.FrameID(), event.EventID(), a.create.frameID, a.create.eventID,
		)
	}

	// Check that server is allowed in the frame by the m.frame.federate flag.
	if err := a.create.DomainAllowed(string(sender.Domain())); err != nil {
		return err
	}

	// Check that event is a state event.
	// Check that the state key matches the server sending this event.
	// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L158
	switch event.Version() {
	default:
		if !event.StateKeyEquals(string(sender.Domain())) {
			return errorf("alias state_key does not match sender domain, %q != %q", sender.Domain(), *event.StateKey())
		}
	}

	return nil
}

// powerLevelsEventAllowed checks whether the m.frame.power_levels event is allowed.
// It returns an error if the event is not allowed or if there was a problem
// loading the auth events needed.
func (a *allowerContext) powerLevelsEventAllowed(event PDU) error {
	allower, err := a.newEventAllower(event.SenderID())
	if err != nil {
		return err
	}

	// power level events must pass the default checks.
	// These checks will catch if the user has a high enough level to set a m.frame.power_levels state event.
	if err = allower.commonChecks(event); err != nil {
		return err
	}

	// Parse the power levels.
	newPowerLevels, err := PowerLevelContentFromEvent(event)
	if err != nil {
		return err
	}

	// Check that the user levels are all valid user IDs
	// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1063
	for senderID := range newPowerLevels.Users {
		sender, err := a.userIDQuerier(a.frameID, spec.SenderID(senderID))
		if err != nil {
			return err
		}
		if !isValidUserID(sender.String()) {
			return errorf("Not a valid user ID: %q", senderID)
		}
	}

	// Grab the old levels so that we can compare new the levels against them.
	oldPowerLevels := a.powerLevels
	senderLevel := oldPowerLevels.UserLevel(event.SenderID())

	// Check that the changes in event levels are allowed.
	if err = checkEventLevels(senderLevel, oldPowerLevels, newPowerLevels); err != nil {
		return err
	}

	// Check that the changes in notification levels are allowed.
	verImpl, err := GetFrameVersion(event.Version())
	if err != nil {
		return nil
	}
	if err = verImpl.CheckNotificationLevels(senderLevel, oldPowerLevels, newPowerLevels); err != nil {
		return err
	}

	// Check that the changes in user levels are allowed.
	return checkUserLevels(senderLevel, event.SenderID(), oldPowerLevels, newPowerLevels)
}


// checkEventLevels checks that the changes in event levels are allowed.
func checkEventLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	type levelPair struct {
		old int64
		new int64
	}
	// Build a list of event levels to check.
	// This differs slightly in behaviour from the code in synapse because it will use the
	// default value if a level is not present in one of the old or new events.

	// First add all the named levels.
	levelChecks := []levelPair{
		{oldPowerLevels.Ban, newPowerLevels.Ban},
		{oldPowerLevels.Invite, newPowerLevels.Invite},
		{oldPowerLevels.Kick, newPowerLevels.Kick},
		{oldPowerLevels.Redact, newPowerLevels.Redact},
		{oldPowerLevels.StateDefault, newPowerLevels.StateDefault},
		{oldPowerLevels.EventsDefault, newPowerLevels.EventsDefault},
	}

	// Then add checks for each event key in the new levels.
	// We use the default values for non-state events when applying the checks.
	// TDO: the per event levels do not distinguish between state and non-state events.
	// However the default values do make that distinction. We may want to change this.
	// For example if there is an entry for "my.custom.type" events it sets the level
	// for sending the event with and without a "state_key". But if there is no entry
	// for "my.custom.type it will use the state default when sent with a "state_key"
	// and will use the event default when sent without.
	const (
		isStateEvent = false
	)
	for eventType := range newPowerLevels.Events {
		levelChecks = append(levelChecks, levelPair{
			oldPowerLevels.EventLevel(eventType, isStateEvent),
			newPowerLevels.EventLevel(eventType, isStateEvent),
		})
	}

	// Then add checks for each event key in the old levels.
	// Some of these will be duplicates of the ones added using the keys from
	// the new levels. But it doesn't hurt to run the checks twice for the same level.
	for eventType := range oldPowerLevels.Events {
		levelChecks = append(levelChecks, levelPair{
			oldPowerLevels.EventLevel(eventType, isStateEvent),
			newPowerLevels.EventLevel(eventType, isStateEvent),
		})
	}

	// Check each of the levels in the list.
	for _, level := range levelChecks {
		// Check if the level is being changed.
		if level.old == level.new {
			// Levels are always allowed to stay the same.
			continue
		}

		// Users are allowed to change the level for an event if:
		//   * the old level was less than or equal to their own
		//   * the new level was less than or equal to their own
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1134

		// Check if the user is trying to set any of the levels to above their own.
		if senderLevel < level.new {
			return errorf(
				"sender with level %d is not allowed to change level from %d to %d"+
					" because the new level is above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}

		// Check if the user is trying to set a level that was above their own.
		if senderLevel < level.old {
			return errorf(
				"sender with level %d is not allowed to change level from %d to %d"+
					" because the current level is above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}
	}

	return nil
}

// checkUserLevels checks that the changes in user levels are allowed.
func checkUserLevels(senderLevel int64, senderID spec.SenderID, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	type levelPair struct {
		old int64
		new int64
	}

	// Build a list of user levels to check.
	userLevelChecks := map[spec.SenderID]levelPair{}
	for userSenderID := range newPowerLevels.Users {
		userLevelChecks[spec.SenderID(userSenderID)] = levelPair{
			old: oldPowerLevels.UserLevel(spec.SenderID(userSenderID)),
			new: newPowerLevels.UserLevel(spec.SenderID(userSenderID)),
		}
	}

	// also add old levels to check for e.g. deletions
	for userSenderID := range oldPowerLevels.Users {
		userLevelChecks[spec.SenderID(userSenderID)] = levelPair{
			old: oldPowerLevels.UserLevel(spec.SenderID(userSenderID)),
			new: newPowerLevels.UserLevel(spec.SenderID(userSenderID)),
		}
	}

	// Check each of the levels in the list.
	for userSenderID, level := range userLevelChecks {
		// Check if the level is being changed.
		if level.old == level.new {
			// Levels are always allowed to stay the same.
			continue
		}

		// Users are allowed to change the level of other users if:
		//   * the old level was less than their own
		//   * the new level was less than or equal to their own
		// They are allowed to change their own level if:
		//   * the new level was less than or equal to their own
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1126-L1127
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L1134

		// Check if the user is trying to set any of the levels to above their own.
		if senderLevel < level.new {
			return errorf(
				"sender %q with level %d is not allowed change user %q level from %d to %d"+
					" because the new level is above the level of the sender",
				senderID, senderLevel, userSenderID, level.old, level.new,
			)
		}

		// Check if the user is changing their own user level.
		if userSenderID == senderID {
			// Users are always allowed to reduce their own user level.
			// We know that the user is reducing their level because of the previous checks.
			continue
		}

		// Check if the user is changing the level that was above or the same as their own.
		if senderLevel <= level.old {
			return errorf(
				"sender %q with level %d is not allowed to change user %q level from %d to %d"+
					" because the old level is equal to or above the level of the sender",
				senderID, senderLevel, userSenderID, level.old, level.new,
			)
		}
	}

	return nil
}

// checkNotificationLevels checks that the changes in notification levels are allowed.
func checkNotificationLevels(senderLevel int64, oldPowerLevels, newPowerLevels PowerLevelContent) error {
	type levelPair struct {
		old    int64
		new    int64
		userID string
	}
	notificationLevelChecks := []levelPair{}

	// Then add checks for each notification key in the new levels.
	for notification := range newPowerLevels.Notifications {
		notificationLevelChecks = append(notificationLevelChecks, levelPair{
			oldPowerLevels.NotificationLevel(notification),
			newPowerLevels.NotificationLevel(notification),
			notification,
		})
	}

	// Then add checks for each notification key in the old levels.
	// Some of these will be duplicates of the ones added using the keys from
	// the new levels. But it doesn't hurt to run the checks twice for the same level.
	for notification := range oldPowerLevels.Notifications {
		notificationLevelChecks = append(notificationLevelChecks, levelPair{
			oldPowerLevels.NotificationLevel(notification),
			newPowerLevels.NotificationLevel(notification),
			notification,
		})
	}

	// Check each of the levels in the list.
	for _, level := range notificationLevelChecks {
		// Check if the level is being changed.
		if level.old == level.new {
			// Levels are always allowed to stay the same.
			continue
		}

		// Users are allowed to change the notification level if:
		//   * If the current value is less than or equal to the `sender`'s current power level
		//   * If the new value is less than or equal to the `sender`'s current power level

		// Check if the user is trying to set any of the levels to above their own.
		if senderLevel < level.new {
			return errorf(
				"sender with level %d is not allowed change notification level from %d to %d"+
					" because the new level is above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}

		// Check if the user is changing the level that was above or the same as their own.
		if senderLevel <= level.old {
			return errorf(
				"sender with level %d is not allowed to change notification level from %d to %d"+
					" because the old level is equal to or above the level of the sender",
				senderLevel, level.old, level.new,
			)
		}
	}

	return nil
}

// redactEventAllowed checks whether the m.frame.redaction event is allowed to
// enter the DAG of a frame. Note that for v1, v2 frames, this doesn't check if
// the redactor is the sender of the redacted event, and for frames >= v3, this
// doesn't provide substantial checks other than some basic checks (e.g.
// membership) on the event.
// It returns an error if the event is not allowed or if there was a problem
// loading the auth events needed.
func (a *allowerContext) redactEventAllowed(event PDU) error {
	allower, err := a.newEventAllower(event.SenderID())
	if err != nil {
		return err
	}

	// redact events must pass the default checks,
	if err = allower.commonChecks(event); err != nil {
		return err
	}

	frameVersion := allower.create.FrameVersion
	if frameVersion != nil && *frameVersion != "1" && *frameVersion != "2" {
		// We always accept redaction events into the DAG for frames >= v3 after the
		// very basic checks.
		return nil
	}

	redactDomain, err := domainFromID(event.Redacts())
	if err != nil {
		return err
	}

	// Servers are always allowed to redact their own messages.
	// This is so that users can redact their own messages, but since
	// we don't know which user ID sent the message being redacted
	// the only check we can do is to compare the domains of the
	// sender and the redacted event.
	// We leave it up to the sending server to implement the additional checks
	// to ensure that only events that should be redacted are redacted.
	sender, err := a.userIDQuerier(a.frameID, event.SenderID())
	if err != nil {
		return err
	}
	if string(sender.Domain()) == redactDomain {
		return nil
	}

	// Otherwise the sender must have enough power.
	// This allows frame admins and ops to redact messages sent by other servers.
	senderLevel := allower.powerLevels.UserLevel(event.SenderID())
	redactLevel := allower.powerLevels.Redact
	if senderLevel >= redactLevel {
		return nil
	}

	return errorf(
		"%q is not allowed to redact message from %q. %d < %d",
		sender, redactDomain, senderLevel, redactLevel,
	)
}

// defaultEventAllowed checks whether the event is allowed by the default
// checks for events.
// It returns an error if the event is not allowed or if there was a
// problem loading the auth events needed.
func (a *allowerContext) defaultEventAllowed(event PDU) error {
	allower, err := a.newEventAllower(event.SenderID())
	if err != nil {
		return err
	}
	return allower.commonChecks(event)
}

// An eventAllower has the information needed to authorise all events types
// other than m.frame.create, m.frame.member and m.frame.aliases which are special.
type eventAllower struct {
	*allowerContext
	// The content of the m.frame.member event for the sender.
	member MemberContent
}

// newEventAllower loads the information needed to authorise an event sent
// by a given user ID from the auth events.
func (a *allowerContext) newEventAllower(senderID spec.SenderID) (e eventAllower, err error) {
	e.allowerContext = a
	if e.member, err = MemberContentFromAuthEvents(a.provider, senderID); err != nil {
		return
	}
	return
}

// commonChecks does the checks that are applied to all events types other than
// m.frame.create, m.frame.member, or m.frame.alias.
func (e *eventAllower) commonChecks(event PDU) error {
	if event.FrameID() != e.create.frameID {
		return errorf(
			"create event has different frameID: %q (%s) != %q (%s)",
			event.FrameID(), event.EventID(), e.create.frameID, e.create.eventID,
		)
	}

	stateKey := event.StateKey()
	userID, err := e.userIDQuerier(e.frameID, event.SenderID())
	if err != nil {
		return err
	}
	if userID == nil {
		return errorf("userID not found for sender %q in frame %q", event.SenderID(), event.FrameID())
	}
	if err := e.create.UserIDAllowed(*userID); err != nil {
		return err
	}

	// Check that the sender is in the frame.
	// Every event other than m.frame.create, m.frame.member and m.frame.aliases require this.
	if e.member.Membership != spec.Join {
		return errorf("sender %q not in frame", event.SenderID())
	}

	senderLevel := e.powerLevels.UserLevel(event.SenderID())
	eventLevel := e.powerLevels.EventLevel(event.Type(), stateKey != nil)
	if senderLevel < eventLevel {
		return errorf(
			"sender %q is not allowed to send event. %d < %d",
			event.SenderID(), senderLevel, eventLevel,
		)
	}

	// Check that all state_keys that begin with '@' are only updated by users
	// with that ID.
	if stateKey != nil && len(*stateKey) > 0 && (*stateKey)[0] == '@' {
		if spec.SenderID(*stateKey) != event.SenderID() {
			return errorf(
				"sender %q is not allowed to modify the state belonging to %q",
				event.SenderID(), *stateKey,
			)
		}
	}

	// TDO: Implement other restrictions on state_keys required by the specification.
	// However as synapse doesn't implement those checks at the moment we'll hold off
	// so that checks between the two codebases don't diverge too much.

	return nil
}

// A membershipAllower has the information needed to authenticate a m.frame.member event
type membershipAllower struct {
	*allowerContext
	frameVersionImpl IFrameVersion
	// The m.frame.third_party_invite content referenced by this event.
	thirdPartyInvite ThirdPartyInviteContent
	// The user ID of the user whose membership is changing.
	targetID string
	// The user ID of the user who sent the membership event.
	senderID string
	// The membership of the user who sent the membership event.
	senderMember MemberContent
	// The previous membership of the user whose membership is changing.
	oldMember MemberContent
	// The new membership of the user if this event is accepted.
	newMember MemberContent
}

// newMembershipAllower loads the information needed to authenticate the m.frame.member event
// from the auth events.
func (a *allowerContext) newMembershipAllower(authEvents AuthEventProvider, event PDU) (m membershipAllower, err error) { // nolint: gocyclo
	m.allowerContext = a
	m.frameVersionImpl, err = GetFrameVersion(event.Version())
	if err != nil {
		return
	}
	stateKey := event.StateKey()
	if stateKey == nil {
		err = errorf("m.frame.member must be a state event")
		return
	}
	// TDO: Check that the IDs are valid user IDs. (for frame versions < pseudoIDs)
	m.targetID = *stateKey
	m.senderID = string(event.SenderID())
	if m.newMember, err = MemberContentFromEvent(event); err != nil {
		return
	}
	if m.oldMember, err = MemberContentFromAuthEvents(authEvents, spec.SenderID(m.targetID)); err != nil {
		return
	}
	if m.senderMember, err = MemberContentFromAuthEvents(authEvents, spec.SenderID(m.senderID)); err != nil {
		return
	}
	// If this event comes from a third_party_invite, we need to check it against the original event.
	if m.newMember.ThirdPartyInvite != nil {
		token := m.newMember.ThirdPartyInvite.Signed.Token
		if m.thirdPartyInvite, err = ThirdPartyInviteContentFromAuthEvents(authEvents, token); err != nil {
			return
		}
	}
	return
}

// membershipAllowed checks whether the membership event is allowed
func (m *membershipAllower) membershipAllowed(event PDU) error { // nolint: gocyclo
	if m.create.frameID != event.FrameID() {
		return errorf(
			"create event has different frameID: %q (%s) != %q (%s)",
			event.FrameID(), event.EventID(), m.create.frameID, m.create.eventID,
		)
	}

	var sender *spec.UserID
	var err error
	if event.Type() == spec.MFrameMember {
		mapping := MemberContent{}
		if err := json.Unmarshal(event.Content(), &mapping); err != nil {
			return err
		}
		if mapping.MXIDMapping != nil {
			sender, err = spec.NewUserID(mapping.MXIDMapping.UserID, true)
			if err != nil {
				return err
			}
		}
	}

	if sender == nil {
		sender, err = m.userIDQuerier(m.frameID, spec.SenderID(m.senderID))
		if err != nil {
			return err
		}
	}

	if sender == nil {
		return errorf("userID not found for sender %q in frame %q", m.senderID, event.FrameID())
	}
	if err := m.create.UserIDAllowed(*sender); err != nil {
		return err
	}

	// Special case the first join event in the frame to allow the creator to join.
	// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L328
	if m.targetID == m.create.Creator &&
		m.newMember.Membership == spec.Join &&
		m.senderID == m.targetID &&
		len(event.PrevEventIDs()) == 1 {

		// Grab the event ID of the previous event.
		prevEventID := event.PrevEventIDs()[0]

		if prevEventID == m.create.eventID {
			// If this is the frame creator joining the frame directly after the
			// the create event, then allow.
			return nil
		}
		// Otherwise fall back to the normal checks.
	}

	if m.newMember.Membership == spec.Invite && m.newMember.ThirdPartyInvite != nil {
		// Special case third party invites
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L393
		return m.membershipAllowedFromThirdPartyInvite()
	}

	if m.targetID == m.senderID {
		// If the state_key and the sender are the same then this is an attempt
		// by a user to update their own membership.
		return m.membershipAllowedSelf()
	}
	// Otherwise this is an attempt to modify the membership of somebody else.
	return m.membershipAllowedOther()
}

func (m *membershipAllower) membershipAllowedSelfForRestrictedJoin() error {
	// Special case for restricted frame joins, where we will check if the membership
	// event is signed by one of the allowed servers in the join rule content.

	if err := m.frameVersionImpl.CheckRestrictedJoinsAllowed(); err != nil {
		return errorf("restricted joins are not supported in this frame version")
	}

	// In the case that the user is already joined, invited or there is no
	// authorised via server, we should treat the join rule as if it's invite.
	if m.oldMember.Membership == spec.Join || m.oldMember.Membership == spec.Invite || m.newMember.AuthorisedVia == "" {
		m.joinRule.JoinRule = spec.Invite
		return nil
	}

	// Otherwise, we have to work out if the server that produced the join was
	// authorised to do so. This requires the membership event to contain a
	// 'join_authorised_via_users_server' key, containing the user ID of a user
	// in the frame that should have a suitable power level to issue invites.
	// If no such key is specified then we should reject the join.
	switch m.frameVersionImpl.Version() {
	default:
		if _, _, err := SplitID('@', m.newMember.AuthorisedVia); err != nil {
			return errorf("the 'join_authorised_via_users_server' contains an invalid value %q", m.newMember.AuthorisedVia)
		}
	}

	// If the nominated user ID is valid then there are two things that we
	// need to check. First of all, is the user joined to the frame?
	otherMember, err := m.provider.Member(spec.SenderID(m.newMember.AuthorisedVia))
	if err != nil {
		return errorf("failed to find the membership event for 'join_authorised_via_users_server' user %q", m.newMember.AuthorisedVia)
	}
	if otherMember == nil {
		return errorf("failed to find the membership event for 'join_authorised_via_users_server' user %q", m.newMember.AuthorisedVia)
	}
	otherMembership, err := otherMember.Membership()
	if err != nil {
		return errorf("failed to find the membership status for 'join_authorised_via_users_server' user %q", m.newMember.AuthorisedVia)
	}
	if otherMembership != spec.Join {
		return errorf("the nominated 'join_authorised_via_users_server' user %q is not joined to the frame", m.newMember.AuthorisedVia)
	}

	// And secondly, does the user have the power to issue invites in the frame?
	if pl := m.powerLevels.UserLevel(spec.SenderID(m.newMember.AuthorisedVia)); pl < m.powerLevels.Invite {
		return errorf("the nominated 'join_authorised_via_users_server' user %q does not have permission to invite (%d < %d)", m.newMember.AuthorisedVia, pl, m.powerLevels.Invite)
	}

	// At this point all of the checks have proceeded, so continue as if
	// the frame is a public frame.
	m.joinRule.JoinRule = spec.Public
	return nil
}

// membershipAllowedFronThirdPartyInvite determines if the member events is following
// up the third_party_invite event it claims.
func (m *membershipAllower) membershipAllowedFromThirdPartyInvite() error {
	// Check if the event's target matches with the Coddy ID provided by the
	// identity server.
	if m.targetID != m.newMember.ThirdPartyInvite.Signed.MXID {
		return errorf(
			"The invite target %s doesn't match with the Coddy ID provided by the identity server %s",
			m.targetID, m.newMember.ThirdPartyInvite.Signed.MXID,
		)
	}
	// Marshal the "signed" so it can be verified by VerifyJSON.
	marshalledSigned, err := json.Marshal(m.newMember.ThirdPartyInvite.Signed)
	if err != nil {
		return err
	}
	// Check each signature with each public key. If one signature could be
	// verified with one public key, accept the event.
	for _, publicKey := range m.thirdPartyInvite.PublicKeys {
		for domain, signatures := range m.newMember.ThirdPartyInvite.Signed.Signatures {
			for keyID := range signatures {
				if strings.HasPrefix(keyID, "ed25519") {
					if err = VerifyJSON(
						domain, KeyID(keyID),
						ed25519.PublicKey(publicKey.PublicKey),
						marshalledSigned,
					); err == nil {
						return nil
					}
				}
			}
		}
	}
	return errorf("Couldn't verify signature on third-party invite for %s", m.targetID)
}

// membershipAllowedSelf determines if the change made by the user to their own membership is allowed.
func (m *membershipAllower) membershipAllowedSelf() error { // nolint: gocyclo
	// NOTSPEC: Leave -> Leave is benign but not allowed according to the Coddy spec.
	// We allow this because of an issue regarding Synapse incorrectly accepting this event.
	if m.oldMember.Membership == spec.Leave && m.newMember.Membership == spec.Leave {
		return nil
	}

	switch m.newMember.Membership {
	case spec.Knock:
		if m.joinRule.JoinRule != spec.Knock && m.joinRule.JoinRule != spec.KnockRestricted {
			return m.membershipFailed(
				"join rule %q does not allow knocking", m.joinRule.JoinRule,
			)
		}
		// A user that is not in the frame is allowed to knock if the join
		// rules are "knock" and they are not already joined to, invited to
		// or banned from the frame.
		// MSC3787 extends this: the behaviour above is also permitted if the
		// join rules are "knock_restricted"
		return m.frameVersionImpl.CheckKnockingAllowed(m)
	case spec.Join:
		if m.oldMember.Membership == spec.Leave && (m.joinRule.JoinRule == spec.Restricted || m.joinRule.JoinRule == spec.KnockRestricted) {
			if err := m.membershipAllowedSelfForRestrictedJoin(); err != nil {
				return err
			}
		}
		// A user that is not in the frame is allowed to join if the frame
		// join rules are "public".
		if m.oldMember.Membership == spec.Leave && m.joinRule.JoinRule == spec.Public {
			return nil
		}
		// An invited user is always allowed to join, regardless of the join rule
		if m.oldMember.Membership == spec.Invite {
			return nil
		}
		// A joined user is allowed to update their join.
		if m.oldMember.Membership == spec.Join {
			return nil
		}
		return m.membershipFailed(
			"join rule %q forbids it", m.joinRule.JoinRule,
		)

	case spec.Leave:
		switch m.oldMember.Membership {
		case spec.Join:
			// A joined user is allowed to leave the frame.
			return nil
		case spec.Invite:
			// An invited user can reject the invite.
			return nil
		case spec.Knock:
			// A knocking user can cancel their knock.
			return nil
		default:
			return m.membershipFailed(
				"sender cannot leave from membership state %q",
				m.oldMember.Membership,
			)
		}

	case spec.Invite, spec.Ban:
		return m.membershipFailed(
			"sender cannot set their own membership to %q", m.newMember.Membership,
		)

	default:
		return m.membershipFailed(
			"membership %q is unknown", m.newMember.Membership,
		)
	}
}

func allowRestrictedJoins() error {
	return nil
}

func checkKnocking(m *membershipAllower) error {
	supported := m.joinRule.JoinRule == spec.Restricted || m.joinRule.JoinRule == spec.KnockRestricted
	if !supported {
		return m.membershipFailed(
			"frame version %q does not support knocking on frames with join rule %q",
			m.frameVersionImpl.Version(),
			m.joinRule.JoinRule,
		)
	}
	switch m.oldMember.Membership {

	case spec.Join, spec.Invite, spec.Ban:
		// The user is already joined, invited or banned, therefore they
		// can't knock.
		return m.membershipFailed(
			"sender is already joined/invited/banned",
		)
	}
	// A non-joined, non-invited, non-banned user is allowed to knock.
	return nil
}

// membershipAllowedOther determines if the user is allowed to change the membership of another user.
func (m *membershipAllower) membershipAllowedOther() error { // nolint: gocyclo
	senderLevel := m.powerLevels.UserLevel(spec.SenderID(m.senderID))
	targetLevel := m.powerLevels.UserLevel(spec.SenderID(m.targetID))

	// You may only modify the membership of another user if you are in the frame.
	if m.senderMember.Membership != spec.Join {
		return errorf("sender %q is not in the frame", m.senderID)
	}

	switch m.newMember.Membership {
	case spec.Ban:
		// A user may ban another user if their level is high enough
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L463
		if senderLevel >= m.powerLevels.Ban && senderLevel > targetLevel {
			return nil
		}
		return m.membershipFailed(
			"sender has insufficient power to ban (sender level %d, target level %d, ban level %d)",
			senderLevel, targetLevel, m.powerLevels.Ban,
		)

	case spec.Leave:
		// A user may unban another user if their level is high enough.
		// This is doesn't require the same power_level checks as banning.
		// You can unban someone with higher power_level than you.
		// https://github.com/coddy-org/synapse/blob/v0.18.5/synapse/api/auth.py#L451
		if m.oldMember.Membership == spec.Ban {
			if senderLevel >= m.powerLevels.Ban {
				return nil
			}
			return m.membershipFailed(
				"sender has insufficient power to unban (sender level %d, ban level %d)",
				senderLevel, m.powerLevels.Ban,
			)
		}
		// A user may kick another user if their level is high enough.
		// TDO: You can kick a user that was already kicked, or has left the frame, or was
		// never in the frame in the first place. Do we want to allow these redundant kicks?
		if senderLevel >= m.powerLevels.Kick && senderLevel > targetLevel {
			return nil
		}
		return m.membershipFailed(
			"sender has insufficient power to kick (sender level %d, target level %d, kick level %d)",
			senderLevel, targetLevel, m.powerLevels.Kick,
		)

	case spec.Invite:
		// A user may only invite another user if they have sufficient power
		// to do so.
		if senderLevel < m.powerLevels.Invite {
			return m.membershipFailed(
				"sender has insufficient power to invite (sender level %d, invite level %d)",
				senderLevel, m.powerLevels.Invite,
			)
		}

		switch m.oldMember.Membership {
		case spec.Join, spec.Ban:
			// A user may invite another user if they haven't joined or have
			// already joined and left before re-inviting.
			return m.membershipFailed(
				"target cannot be invited when their membership is %q",
				m.oldMember.Membership,
			)
		default:
			// A user may invite another user if they:
			// - haven't joined the frame yet
			// - joined before but have since left
			// - were already invite
			// - were already knock
			return nil
		}

	case spec.Knock, spec.Join:
		return m.membershipFailed(
			"sender cannot set membership of another user to %q", m.newMember.Membership,
		)

	default:
		return m.membershipFailed(
			"membership %q is unknown", m.newMember.Membership,
		)
	}
}

// membershipFailed returns a error explaining why the membership change was disallowed.
func (m *membershipAllower) membershipFailed(format string, args ...interface{}) error {
	if m.senderID == m.targetID {
		return errorf(
			"%q is not allowed to change their membership from %q to %q as "+format,
			append([]interface{}{m.targetID, m.oldMember.Membership, m.newMember.Membership}, args...)...,
		)
	}

	return errorf(
		"%q is not allowed to change the membership of %q from %q to %q as "+format,
		append([]interface{}{m.senderID, m.targetID, m.oldMember.Membership, m.newMember.Membership}, args...)...,
	)
}
