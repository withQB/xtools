package xtools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/withqb/xtools/spec"
	"github.com/withqb/xutil"
)

type FrameQuerier interface {
	IsKnownFrame(ctx context.Context, frameID spec.FrameID) (bool, error)
}

type StateQuerier interface {
	GetAuthEvents(ctx context.Context, event PDU) (AuthEventProvider, error)
	GetState(ctx context.Context, frameID spec.FrameID, stateWanted []StateKeyTuple) ([]PDU, error)
}

type LatestEvents struct {
	FrameExists   bool
	StateEvents  []PDU
	PrevEventIDs []string
	Depth        int64
}

type FederatedInviteClient interface {
	SendInvite(ctx context.Context, event PDU, strippedState []InviteStrippedState) (PDU, error)
	SendInviteV3(ctx context.Context, event ProtoEvent, userID spec.UserID, frameVersion FrameVersion, strippedState []InviteStrippedState) (PDU, error)
}

// InviteStrippedState is a cut-down set of fields from frame state
// events that allow the invited server to identify the frame.
type InviteStrippedState struct {
	fields struct {
		Content  spec.RawJSON `json:"content"`
		StateKey *string      `json:"state_key"`
		Type     string       `json:"type"`
		SenderID string       `json:"sender"`
	}
}

// NewInviteStrippedState creates a stripped state event from a
// regular state event.
func NewInviteStrippedState(event PDU) (ss InviteStrippedState) {
	ss.fields.Content = event.Content()
	ss.fields.StateKey = event.StateKey()
	ss.fields.Type = event.Type()
	ss.fields.SenderID = string(event.SenderID())
	return
}

// MarshalJSON implements json.Marshaller
func (i InviteStrippedState) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteStrippedState) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &i.fields)
}

// Content returns the content of the stripped state.
func (i *InviteStrippedState) Content() spec.RawJSON {
	return i.fields.Content
}

// StateKey returns the state key of the stripped state.
func (i *InviteStrippedState) StateKey() *string {
	return i.fields.StateKey
}

// Type returns the type of the stripped state.
func (i *InviteStrippedState) Type() string {
	return i.fields.Type
}

// Sender returns the sender of the stripped state.
func (i *InviteStrippedState) Sender() string {
	return i.fields.SenderID
}

func GenerateStrippedState(
	ctx context.Context, frameID spec.FrameID, stateQuerier StateQuerier,
) ([]InviteStrippedState, error) {
	// "If they are set on the frame, at least the state for m.frame.avatar, m.frame.canonical_alias, m.frame.join_rules, and m.frame.name SHOULD be included."
	// https://matrix.org/docs/spec/client_server/r0.6.0#m-frame-member
	stateWanted := []StateKeyTuple{}
	for _, t := range []string{
		spec.MFrameName, spec.MFrameCanonicalAlias,
		spec.MFrameJoinRules, spec.MFrameAvatar,
		spec.MFrameEncryption, spec.MFrameCreate,
	} {
		stateWanted = append(stateWanted, StateKeyTuple{
			EventType: t,
			StateKey:  "",
		})
	}

	stateEvents, err := stateQuerier.GetState(ctx, frameID, stateWanted)
	if err != nil {
		return []InviteStrippedState{}, err
	}
	if stateEvents != nil {
		inviteState := []InviteStrippedState{}
		for _, event := range stateEvents {
			inviteState = append(inviteState, NewInviteStrippedState(event))
		}
		return inviteState, nil
	}
	return []InviteStrippedState{}, nil
}

func abortIfAlreadyJoined(ctx context.Context, frameID spec.FrameID, invitedUser spec.SenderID, membershipQuerier MembershipQuerier) error {
	membership, err := membershipQuerier.CurrentMembership(ctx, frameID, invitedUser)
	if err != nil {
		xutil.GetLogger(ctx).WithError(err).Error("failed getting user membership")
		return spec.InternalServerError{}

	}
	isAlreadyJoined := (membership == spec.Join)

	if isAlreadyJoined {
		// If the user is joined to the frame then that takes precedence over this
		// invite event. It makes little sense to move a user that is already
		// joined to the frame into the invite state.
		// This could plausibly happen if an invite request raced with a join
		// request for a user. For example if a user was invited to a public
		// frame and they joined the frame at the same time as the invite was sent.
		// The other way this could plausibly happen is if an invite raced with
		// a kick. For example if a user was kicked from a frame in error and in
		// response someone else in the frame re-invited them then it is possible
		// for the invite request to race with the leave event so that the
		// target receives invite before it learns that it has been kicked.
		// There are a few ways this could be plausibly handled in the frameserver.
		// 1) Store the invite, but mark it as retired. That will result in the
		//    permanent rejection of that invite event. So even if the target
		//    user leaves the frame and the invite is retransmitted it will be
		//    ignored. However a new invite with a new event ID would still be
		//    accepted.
		// 2) Silently discard the invite event. This means that if the event
		//    was retransmitted at a later date after the target user had left
		//    the frame we would accept the invite. However since we hadn't told
		//    the sending server that the invite had been discarded it would
		//    have no reason to attempt to retry.
		// 3) Signal the sending server that the user is already joined to the
		//    frame.
		// For now we will implement option 2. Since in the abesence of a retry
		// mechanism it will be equivalent to option 1, and we don't have a
		// signalling mechanism to implement option 3.
		xutil.GetLogger(ctx).Error("user is already joined to frame")
		return spec.Forbidden("user is already joined to frame")
	}
	return nil
}

func createInviteLogger(ctx context.Context, frameID spec.FrameID, inviter spec.UserID, invitee spec.UserID, eventID string) *logrus.Entry {
	return xutil.GetLogger(ctx).WithFields(map[string]interface{}{
		"inviter":  inviter.String(),
		"invitee":  invitee.String(),
		"frame_id":  frameID.String(),
		"event_id": eventID,
	})
}

func setUnsignedFieldForInvite(event PDU, inviteState []InviteStrippedState) error {
	if len(inviteState) == 0 {
		if err := event.SetUnsignedField("invite_frame_state", struct{}{}); err != nil {
			return fmt.Errorf("event.SetUnsignedField: %w", err)
		}
	} else {
		if err := event.SetUnsignedField("invite_frame_state", inviteState); err != nil {
			return fmt.Errorf("event.SetUnsignedField: %w", err)
		}
	}

	return nil
}

func setUnsignedFieldForProtoInvite(event *ProtoEvent, inviteState []InviteStrippedState) error {
	if len(inviteState) == 0 {
		if err := event.SetUnsigned(map[string]interface{}{"invite_frame_state": struct{}{}}); err != nil {
			return fmt.Errorf("event.SetUnsignedField: %w", err)
		}
	} else {
		if err := event.SetUnsigned(map[string]interface{}{"invite_frame_state": inviteState}); err != nil {
			return fmt.Errorf("event.SetUnsignedField: %w", err)
		}
	}

	return nil
}
