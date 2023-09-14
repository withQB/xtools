package xtools

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/withqb/xtools/spec"
	"github.com/withqb/xutil"
)

type HandleMakeJoinInput struct {
	Context           context.Context
	UserID            spec.UserID               // The user wanting to join the frame
	SenderID          spec.SenderID             // The senderID of the user wanting to join the frame
	FrameID            spec.FrameID               // The frame the user wants to join
	FrameVersion       FrameVersion               // The frame version for the frame being joined
	RemoteVersions    []FrameVersion             // Frame versions supported by the remote server
	RequestOrigin     spec.ServerName           // The server that sent the /make_join federation request
	LocalServerName   spec.ServerName           // The name of this local server
	LocalServerInFrame bool                      // Whether this local server has a user currently joined to the frame
	FrameQuerier       RestrictedFrameJoinQuerier // Provides access to potentially required information when processing restricted joins
	UserIDQuerier     spec.UserIDForSender      // Provides userIDs given a senderID

	// Returns a fully built version of the proto event and a list of state events required to auth this event
	BuildEventTemplate func(*ProtoEvent) (PDU, []PDU, error)
}

type HandleMakeJoinResponse struct {
	JoinTemplateEvent ProtoEvent
	FrameVersion       FrameVersion
}

func HandleMakeJoin(input HandleMakeJoinInput) (*HandleMakeJoinResponse, error) {
	if input.FrameQuerier == nil || input.UserIDQuerier == nil {
		panic("Missing valid Querier")
	}

	if input.Context == nil {
		panic("Missing valid Context")
	}

	// Check that the frame that the remote side is trying to join is actually
	// one of the frame versions that they listed in their supported ?ver= in
	// the make_join URL.
	// If it isn't, stop trying to join the frame.
	if !frameVersionSupported(input.FrameVersion, input.RemoteVersions) {
		return nil, spec.IncompatibleFrameVersion(string(input.FrameVersion))
	}

	if input.UserID.Domain() != input.RequestOrigin {
		return nil, spec.Forbidden(fmt.Sprintf("The join must be sent by the server of the user. Origin %s != %s",
			input.RequestOrigin, input.UserID.Domain()))
	}

	// Check if we think we are still joined to the frame
	if !input.LocalServerInFrame {
		return nil, spec.NotFound(fmt.Sprintf("Local server not currently joined to frame: %s", input.FrameID.String()))
	}

	// Check if the restricted join is allowed. If the frame doesn't
	// support restricted joins then this is effectively a no-op.
	authorisedVia, err := MustGetFrameVersion(input.FrameVersion).CheckRestrictedJoin(input.Context, input.LocalServerName, input.FrameQuerier, input.FrameID, input.SenderID)
	switch e := err.(type) {
	case nil:
	case spec.CoddyError:
		xutil.GetLogger(input.Context).WithError(err).Error("checkRestrictedJoin failed")
		return nil, e
	default:
		return nil, spec.InternalServerError{Err: "checkRestrictedJoin failed"}
	}

	// Try building an event for the server
	rawSenderID := string(input.SenderID)
	proto := ProtoEvent{
		SenderID: string(input.SenderID),
		FrameID:   input.FrameID.String(),
		Type:     spec.MFrameMember,
		StateKey: &rawSenderID,
	}
	content := MemberContent{
		Membership:    spec.Join,
		AuthorisedVia: authorisedVia,
	}
	if err = proto.SetContent(content); err != nil {
		return nil, spec.InternalServerError{Err: "builder.SetContent failed"}
	}

	event, state, templateErr := input.BuildEventTemplate(&proto)
	if templateErr != nil {
		return nil, templateErr
	}
	if event == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event"}
	}
	if state == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event state"}
	}
	if event.Type() != spec.MFrameMember {
		return nil, spec.InternalServerError{Err: fmt.Sprintf("expected join event from template builder. got: %s", event.Type())}
	}

	provider := NewAuthEvents(state)
	if err = Allowed(event, &provider, input.UserIDQuerier); err != nil {
		return nil, spec.Forbidden(err.Error())
	}


	makeJoinResponse := HandleMakeJoinResponse{
		JoinTemplateEvent: proto,
		FrameVersion:       input.FrameVersion,
	}
	return &makeJoinResponse, nil
}

func frameVersionSupported(frameVersion FrameVersion, supportedVersions []FrameVersion) bool {
	remoteSupportsVersion := false
	for _, v := range supportedVersions {
		if v == frameVersion {
			remoteSupportsVersion = true
			break
		}
	}

	return remoteSupportsVersion
}

// checkRestrictedJoin finds out whether or not we can assist in processing
// a restricted frame join. If the frame version does not support restricted
// joins then this function returns with no side effects. This returns:
//   - a user ID of an authorising user, typically a user that has power to
//     issue invites in the frame, if one has been found
//   - an error if there was a problem finding out if this was allowable,
//     like if the frame version isn't known or a problem happened talking to
//     the frameserver
func checkRestrictedJoin(
	ctx context.Context,
	localServerName spec.ServerName,
	frameQuerier RestrictedFrameJoinQuerier,
	frameID spec.FrameID, senderID spec.SenderID,
) (string, error) {
	// Get the join rules to work out if the join rule is "restricted".
	joinRulesEvent, err := frameQuerier.CurrentStateEvent(ctx, frameID, spec.MFrameJoinRules, "")
	if err != nil {
		return "", fmt.Errorf("frameQuerier.StateEvent: %w", err)
	}
	if joinRulesEvent == nil {
		// The join rules for the frame don't restrict membership.
		return "", nil
	}
	var joinRules JoinRuleContent
	if err = json.Unmarshal(joinRulesEvent.Content(), &joinRules); err != nil {
		return "", fmt.Errorf("json.Unmarshal: %w", err)
	}

	// If the join rule isn't "restricted" or "knock_restricted" then there's nothing more to do.
	restricted := joinRules.JoinRule == spec.Restricted || joinRules.JoinRule == spec.KnockRestricted
	if !restricted {
		// The join rules for the frame don't restrict membership.
		return "", nil
	}

	// If the user is already invited to the frame then the join is allowed
	// but we don't specify an authorised via user, since the event auth
	// will allow the join anyway.
	if pending, err := frameQuerier.InvitePending(ctx, frameID, senderID); err != nil {
		return "", fmt.Errorf("helpers.IsInvitePending: %w", err)
	} else if pending {
		// The join rules for the frame don't restrict membership.
		return "", nil
	}

	// We need to get the power levels content so that we can determine which
	// users in the frame are entitled to issue invites. We need to use one of
	// these users as the authorising user.
	powerLevelsEvent, err := frameQuerier.CurrentStateEvent(ctx, frameID, spec.MFramePowerLevels, "")
	if err != nil {
		return "", fmt.Errorf("frameQuerier.StateEvent: %w", err)
	}
	if powerLevelsEvent == nil {
		return "", fmt.Errorf("invalid power levels event")
	}
	powerLevels, err := powerLevelsEvent.PowerLevels()
	if err != nil {
		return "", fmt.Errorf("unable to get powerlevels: %w", err)
	}

	resident := true
	// Step through the join rules and see if the user matches any of them.
	for _, rule := range joinRules.Allow {
		// We only understand "m.frame_membership" rules at this point in
		// time, so skip any rule that doesn't match those.
		if rule.Type != spec.MFrameMembership {
			continue
		}

		// See if the frame exists. If it doesn't exist or if it's a stub
		// frame entry then we can't check memberships.
		frameID, err := spec.NewFrameID(rule.FrameID)
		if err != nil {
			continue
		}

		// First of all work out if *we* are still in the frame, otherwise
		// it's possible that the memberships will be out of date.
		targetFrameInfo, err := frameQuerier.RestrictedFrameJoinInfo(ctx, *frameID, senderID, localServerName)
		if err != nil || targetFrameInfo == nil || !targetFrameInfo.LocalServerInFrame {
			// If we aren't in the frame, we can no longer tell if the frame
			// memberships are up-to-date.
			resident = false
			continue
		}

		// At this point we're happy that we are in the frame, so now let's
		// see if the target user is in the frame.
		// If the user is not in the frame then we will skip this rule.
		if !targetFrameInfo.UserJoinedToFrame {
			continue
		}

		// The user is in the frame, so now we will need to authorise the
		// join using the user ID of one of our own users in the frame. Pick
		// one.
		if err != nil || len(targetFrameInfo.JoinedUsers) == 0 {
			// There should always be more than one join event at this point
			// because we are gated behind GetLocalServerInFrame, but y'know,
			// sometimes strange things happen.
			continue
		}

		// For each of the joined users, let's see if we can get a valid
		// membership event.
		for _, user := range targetFrameInfo.JoinedUsers {
			if user.Type() != spec.MFrameMember || user.StateKey() == nil {
				continue // shouldn't happen
			}
			// Only users that have the power to invite should be chosen.
			if powerLevels.UserLevel(spec.SenderID(*user.StateKey())) < powerLevels.Invite {
				continue
			}

			// The join rules restrict membership, our server is in the relevant
			// frames and the user was allowed to join because they belong to one
			// of the allowed frames. Return one of our own local users
			// from within the frame to use as the authorising user ID, so that it
			// can be referred to from within the membership content.
			return *user.StateKey(), nil
		}
	}

	if !resident {
		// The join rules restrict membership but our server isn't currently
		// joined to all of the allowed frames, so we can't actually decide
		// whether or not to allow the user to join. This error code should
		// tell the joining server to try joining via another resident server
		// instead.
		return "", spec.UnableToAuthoriseJoin("This server cannot authorise the join.")
	}

	// The join rules restrict membership, our server is in the relevant
	// frames and the user wasn't joined to join any of the allowed frames
	// and therefore can't join this frame.
	return "", spec.Forbidden("You are not joined to any matching frames.")
}

type HandleSendJoinInput struct {
	Context                   context.Context
	FrameID                    spec.FrameID
	EventID                   string
	JoinEvent                 spec.RawJSON
	FrameVersion               FrameVersion     // The frame version for the frame being joined
	RequestOrigin             spec.ServerName // The server that sent the /make_join federation request
	LocalServerName           spec.ServerName // The name of this local server
	KeyID                     KeyID
	PrivateKey                ed25519.PrivateKey
	Verifier                  JSONVerifier
	MembershipQuerier         MembershipQuerier
	UserIDQuerier             spec.UserIDForSender // Provides userIDs given a senderID
	StoreSenderIDFromPublicID spec.StoreSenderIDFromPublicID
}

type HandleSendJoinResponse struct {
	AlreadyJoined bool
	JoinEvent     PDU
}

// nolint: gocyclo
func HandleSendJoin(input HandleSendJoinInput) (*HandleSendJoinResponse, error) {
	if input.Verifier == nil {
		panic("Missing valid JSONVerifier")
	}
	if input.MembershipQuerier == nil {
		panic("Missing valid StateQuerier")
	}
	if input.UserIDQuerier == nil {
		panic("Missing valid UserIDQuerier")
	}
	if input.Context == nil {
		panic("Missing valid Context")
	}
	if input.StoreSenderIDFromPublicID == nil {
		panic("Missing valid StoreSenderID")
	}

	verImpl, err := GetFrameVersion(input.FrameVersion)
	if err != nil {
		return nil, spec.UnsupportedFrameVersion(fmt.Sprintf("QueryFrameVersionForFrame returned unknown frame version: %s", input.FrameVersion))
	}

	event, err := verImpl.EventFromUntrustedJSON(input.JoinEvent)
	if err != nil {
		return nil, spec.BadJSON("The request body could not be decoded into valid JSON: " + err.Error())
	}

	// Check that a state key is provided.
	if event.StateKey() == nil || event.StateKeyEquals("") {
		return nil, spec.BadJSON("No state key was provided in the join event.")
	}
	if !event.StateKeyEquals(string(event.SenderID())) {
		return nil, spec.BadJSON("Event state key must match the event sender.")
	}

	// Check that the sender belongs to the server that is sending us
	// the request. By this point we've already asserted that the sender
	// and the state key are equal so we don't need to check both.
	sender, err := input.UserIDQuerier(input.FrameID, event.SenderID())
	if err != nil {
		return nil, spec.Forbidden("The sender of the join is invalid")
	} else if sender.Domain() != input.RequestOrigin {
		return nil, spec.Forbidden("The sender does not match the server that originated the request")
	}

	// In pseudoID frames we don't need to hit federation endpoints to get e.g. signing keys,
	// so we can replace the verifier with a more simple one which uses the senderID to verify the event.
	toVerify := sender.Domain()


	// Check that the frame ID is correct.
	if event.FrameID() != input.FrameID.String() {
		return nil, spec.BadJSON(
			fmt.Sprintf(
				"The frame ID in the request path (%q) must match the frame ID in the join event JSON (%q)",
				input.FrameID.String(), event.FrameID(),
			),
		)
	}

	// Check that the event ID is correct.
	if event.EventID() != input.EventID {
		return nil, spec.BadJSON(
			fmt.Sprintf(
				"The event ID in the request path (%q) must match the event ID in the join event JSON (%q)",
				input.EventID, event.EventID(),
			),
		)
	}

	// Check that this is in fact a join event
	membership, err := event.Membership()
	if err != nil {
		return nil, spec.BadJSON("missing content.membership key")
	}
	if membership != spec.Join {
		return nil, spec.BadJSON("membership must be 'join'")
	}

	// Check that the event is signed by the server sending the request.
	redacted, err := verImpl.RedactEventJSON(event.JSON())
	if err != nil {
		xutil.GetLogger(input.Context).WithError(err).Error("RedactEventJSON failed")
		return nil, spec.BadJSON("The event JSON could not be redacted")
	}

	verifyRequests := []VerifyJSONRequest{{
		ServerName:           toVerify,
		Message:              redacted,
		AtTS:                 event.OriginServerTS(),
		ValidityCheckingFunc: StrictValiditySignatureCheck,
	}}
	verifyResults, err := input.Verifier.VerifyJSONs(input.Context, verifyRequests)
	if err != nil {
		xutil.GetLogger(input.Context).WithError(err).Error("keys.VerifyJSONs failed")
		return nil, spec.InternalServerError{}
	}
	if verifyResults[0].Error != nil {
		return nil, spec.Forbidden("Signature check failed: " + verifyResults[0].Error.Error())
	}

	// Check if the user is already in the frame. If they're already in then
	// there isn't much point in sending another join event into the frame.
	// Also check to see if they are banned: if they are then we reject them.
	existingMembership, err := input.MembershipQuerier.CurrentMembership(input.Context, input.FrameID, event.SenderID())
	if err != nil {
		return nil, spec.InternalServerError{Err: "internal server error"}
	}

	alreadyJoined := (existingMembership == spec.Join)
	isBanned := (existingMembership == spec.Ban)

	if isBanned {
		return nil, spec.Forbidden("user is banned")
	}

	// If the membership content contains a user ID for a server that is not
	// ours then we should kick it back.
	var memberContent MemberContent
	if err := json.Unmarshal(event.Content(), &memberContent); err != nil {
		return nil, spec.BadJSON(err.Error())
	}
	if memberContent.AuthorisedVia != "" {
		authorisedVia, err := spec.NewUserID(memberContent.AuthorisedVia, true)
		if err != nil {
			xutil.GetLogger(input.Context).WithError(err).Errorf("The authorising username %q is invalid.", memberContent.AuthorisedVia)
			return nil, spec.BadJSON(fmt.Sprintf("The authorising username %q is invalid.", memberContent.AuthorisedVia))
		}
		if authorisedVia.Domain() != input.LocalServerName {
			xutil.GetLogger(input.Context).Errorf("The authorising username %q does not belong to this server.", authorisedVia.String())
			return nil, spec.BadJSON(fmt.Sprintf("The authorising username %q does not belong to this server.", authorisedVia.String()))
		}
	}

	// Sign the membership event. This is required for restricted joins to work
	// in the case that the authorised via user is one of our own users. It also
	// doesn't hurt to do it even if it isn't a restricted join.
	signed := event.Sign(
		string(input.LocalServerName),
		input.KeyID,
		input.PrivateKey,
	)

	return &HandleSendJoinResponse{
		AlreadyJoined: alreadyJoined,
		JoinEvent:     signed,
	}, nil
}
