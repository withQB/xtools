package xtools

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/withqb/xtools/spec"
	"github.com/withqb/xutil"
	"golang.org/x/crypto/ed25519"
)

type HandleInviteInput struct {
	FrameID          spec.FrameID           // The frame that the user is being invited to join
	FrameVersion     FrameVersion           // The version of the invited to frame
	InvitedUser     spec.UserID           // The user being invited to join the frame
	InvitedSenderID spec.SenderID         // The senderID of the user being invited to join the frame
	InviteEvent     PDU                   // The original invite event
	StrippedState   []InviteStrippedState // A small set of state events that can be used to identify the frame

	KeyID      KeyID              // Used to sign the original invite event
	PrivateKey ed25519.PrivateKey // Used to sign the original invite event
	Verifier   JSONVerifier       // Used to verify the original invite event

	FrameQuerier       FrameQuerier          // Provides information about the frame
	MembershipQuerier MembershipQuerier    // Provides information about the frame's membership
	StateQuerier      StateQuerier         // Provides access to state events
	UserIDQuerier     spec.UserIDForSender // Provides userIDs given a senderID
}

type HandleInviteV3Input struct {
	HandleInviteInput

	InviteProtoEvent    ProtoEvent          // The original invite event
	GetOrCreateSenderID spec.CreateSenderID // Creates, if needed, a new senderID & private key
}

// HandleInvite - Ensures the incoming invite request is valid and signs the event
// to return back to the remote server.
// On success returns a fully formed & signed Invite Event
func HandleInvite(ctx context.Context, input HandleInviteInput) (PDU, error) {
	if input.FrameQuerier == nil || input.MembershipQuerier == nil || input.StateQuerier == nil || input.UserIDQuerier == nil {
		panic("Missing valid Querier")
	}
	if input.Verifier == nil {
		panic("Missing valid JSONVerifier")
	}

	if ctx == nil {
		panic("Missing valid Context")
	}

	// Check that we can accept invites for this frame version.
	verImpl, err := GetFrameVersion(input.FrameVersion)
	if err != nil {
		return nil, spec.UnsupportedFrameVersion(
			fmt.Sprintf("Frame version %q is not supported by this server.", input.FrameVersion),
		)
	}

	// Check that the frame ID is correct.
	if input.InviteEvent.FrameID() != input.FrameID.String() {
		return nil, spec.BadJSON("The frame ID in the request path must match the frame ID in the invite event JSON")
	}

	// Check that the event is signed by the server sending the request.
	redacted, err := verImpl.RedactEventJSON(input.InviteEvent.JSON())
	if err != nil {
		return nil, spec.BadJSON("The event JSON could not be redacted")
	}

	sender, err := input.UserIDQuerier(input.FrameID, input.InviteEvent.SenderID())
	if err != nil {
		return nil, spec.BadJSON("The event JSON contains an invalid sender")
	}
	verifyRequests := []VerifyJSONRequest{{
		ServerName:           sender.Domain(),
		Message:              redacted,
		AtTS:                 input.InviteEvent.OriginServerTS(),
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}}
	verifyResults, err := input.Verifier.VerifyJSONs(ctx, verifyRequests)
	if err != nil {
		xutil.GetLogger(ctx).WithError(err).Error("keys.VerifyJSONs failed")
		return nil, spec.InternalServerError{}
	}
	if verifyResults[0].Error != nil {
		return nil, spec.Forbidden("The invite must be signed by the server it originated on")
	}

	signedEvent := input.InviteEvent.Sign(
		string(input.InvitedUser.Domain()), input.KeyID, input.PrivateKey,
	)

	return handleInviteCommonChecks(ctx, input, signedEvent, *sender)
}

func HandleInviteV3(ctx context.Context, input HandleInviteV3Input) (PDU, error) {
	if input.FrameQuerier == nil || input.MembershipQuerier == nil || input.StateQuerier == nil || input.UserIDQuerier == nil {
		panic("Missing valid Querier")
	}
	if input.Verifier == nil {
		panic("Missing valid JSONVerifier")
	}

	if ctx == nil {
		panic("Missing valid Context")
	}

	// Check that we can accept invites for this frame version.
	verImpl, err := GetFrameVersion(input.FrameVersion)
	if err != nil {
		return nil, spec.UnsupportedFrameVersion(
			fmt.Sprintf("Frame version %q is not supported by this server.", input.FrameVersion),
		)
	}

	// Check that the frame ID is correct.
	if input.InviteProtoEvent.FrameID != input.FrameID.String() {
		return nil, spec.BadJSON("The frame ID in the request path must match the frame ID in the invite event JSON")
	}

	// NOTE: If we already have a senderID for this user in this frame,
	// this could be because they are already invited/joined or were previously.
	// In that case, use the existing senderID to complete this invite event.
	// Otherwise we need to create a new senderID
	invitedSenderID, signingKey, err := input.GetOrCreateSenderID(ctx, input.InvitedUser, input.FrameID, string(input.FrameVersion))
	if err != nil {
		xutil.GetLogger(ctx).WithError(err).Error("GetOrCreateSenderID failed")
		return nil, spec.InternalServerError{}
	}

	input.InviteProtoEvent.StateKey = (*string)(&invitedSenderID)

	// Sign the event so that other servers will know that we have received the invite.
	keyID := KeyID("ed25519:1")
	origin := spec.ServerName(invitedSenderID)
	fullEventBuilder := verImpl.NewEventBuilderFromProtoEvent(&input.InviteProtoEvent)
	fullEvent, err := fullEventBuilder.Build(time.Now(), origin, keyID, signingKey)
	if err != nil {
		xutil.GetLogger(ctx).WithError(err).Error("failed building invite event")
		return nil, spec.InternalServerError{}
	}

	return handleInviteCommonChecks(ctx, input.HandleInviteInput, fullEvent, spec.UserID{})
}

func handleInviteCommonChecks(ctx context.Context, input HandleInviteInput, event PDU, sender spec.UserID) (PDU, error) {
	isKnownFrame, err := input.FrameQuerier.IsKnownFrame(ctx, input.FrameID)
	if err != nil {
		xutil.GetLogger(ctx).WithError(err).Error("failed querying known frame")
		return nil, spec.InternalServerError{}
	}

	logger := createInviteLogger(ctx, input.FrameID, sender, input.InvitedUser, event.EventID())
	logger.WithFields(logrus.Fields{
		"frame_version":     event.Version(),
		"frame_info_exists": isKnownFrame,
	}).Debug("processing incoming federation invite event")

	inviteState := input.StrippedState
	if len(inviteState) == 0 {
		inviteState, err = GenerateStrippedState(ctx, input.FrameID, input.StateQuerier)
		if err != nil {
			xutil.GetLogger(ctx).WithError(err).Error("failed generating stripped state")
			return nil, spec.InternalServerError{}
		}
	}

	if isKnownFrame {
		if len(inviteState) == 0 {
			xutil.GetLogger(ctx).WithError(err).Error("failed generating stripped state for known frame")
			return nil, spec.InternalServerError{}
		}
		err := abortIfAlreadyJoined(ctx, input.FrameID, input.InvitedSenderID, input.MembershipQuerier)
		if err != nil {
			return nil, err
		}
	}

	err = setUnsignedFieldForInvite(event, inviteState)
	if err != nil {
		return nil, err
	}

	return event, nil
}
