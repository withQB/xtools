package xtools

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/withqb/xtools/spec"
)

type GetLatestEvents func(ctx context.Context, frameID spec.FrameID, eventsNeeded []StateKeyTuple) (LatestEvents, error)

type PerformInviteInput struct {
	FrameID        spec.FrameID // The frame the user is being invited to join
	FrameVersion   FrameVersion
	Inviter       spec.UserID           // The user doing the inviting
	Invitee       spec.UserID           // The user being invited join the frame
	IsTargetLocal bool                  // Whether the user being invited is local to this server
	EventTemplate ProtoEvent            // The original invite event
	StrippedState []InviteStrippedState // A small set of state events that can be used to identify the frame
	KeyID         KeyID
	SigningKey    ed25519.PrivateKey
	EventTime     time.Time

	MembershipQuerier         MembershipQuerier    // Provides information about the frame's membership
	StateQuerier              StateQuerier         // Provides access to state events
	UserIDQuerier             spec.UserIDForSender // Provides userID for a given senderID
	SenderIDQuerier           spec.SenderIDForUser // Provides senderID for a given userID
	SenderIDCreator           spec.CreateSenderID
	EventQuerier              GetLatestEvents
	StoreSenderIDFromPublicID spec.StoreSenderIDFromPublicID // Creates the senderID -> userID for the frame creator
}

// PerformInvite - Performs all the checks required to validate the invite is allowed
// to happen.
// On success will return either nothing (in the case of inviting a local user) or
// a fully formed & signed Invite Event (in the case of inviting a remote user)
// nolint:gocyclo
func PerformInvite(ctx context.Context, input PerformInviteInput, fedClient FederatedInviteClient) (PDU, error) {
	if input.MembershipQuerier == nil || input.StateQuerier == nil || input.UserIDQuerier == nil ||
		input.SenderIDQuerier == nil || input.SenderIDCreator == nil || input.EventQuerier == nil {
		panic("Missing valid Querier")
	}
	if ctx == nil {
		panic("Missing valid Context")
	}

	logger := createInviteLogger(ctx, input.FrameID, input.Inviter, input.Invitee, "")
	logger.WithFields(logrus.Fields{
		"frame_version": input.FrameVersion,
		"target_local": input.IsTargetLocal,
		"origin_local": true,
	}).Debug("processing invite event")

	inviteState := input.StrippedState
	if len(inviteState) == 0 {
		var err error
		inviteState, err = GenerateStrippedState(ctx, input.FrameID, input.StateQuerier)
		if err != nil {
			logger.WithError(err).Error("failed generating stripped state")
			return nil, spec.InternalServerError{}
		}
	}

	err := setUnsignedFieldForProtoInvite(&input.EventTemplate, inviteState)
	if err != nil {
		return nil, err
	}

	// Check that we can accept invites for this frame version.
	verImpl, err := GetFrameVersion(input.FrameVersion)
	if err != nil {
		return nil, spec.UnsupportedFrameVersion(
			fmt.Sprintf("Frame version %q is not supported by this server.", input.FrameVersion),
		)
	}

	invitedSenderID, err := input.SenderIDQuerier(input.FrameID, input.Invitee)
	if err != nil {
		return nil, err
	}

	if invitedSenderID != nil {
		err = abortIfAlreadyJoined(ctx, input.FrameID, *invitedSenderID, input.MembershipQuerier)
		if err != nil {
			return nil, err
		}
	}

	stateNeeded, err := StateNeededForProtoEvent(&input.EventTemplate)
	if err != nil {
		return nil, err
	}

	if len(stateNeeded.Tuples()) == 0 {
		return nil, spec.InternalServerError{}
	}

	latestEvents, err := input.EventQuerier(ctx, input.FrameID, stateNeeded.Tuples())
	if err != nil {
		return nil, err
	}

	if !latestEvents.FrameExists {
		return nil, spec.InternalServerError{}
	}

	input.EventTemplate.Depth = latestEvents.Depth

	authEvents := NewAuthEvents(nil)

	for _, event := range latestEvents.StateEvents {
		err := authEvents.AddEvent(event)
		if err != nil {
			return nil, fmt.Errorf("authEvents.AddEvent: %w", err)
		}
	}

	refs, err := stateNeeded.AuthEventReferences(&authEvents)
	if err != nil {
		return nil, fmt.Errorf("eventsNeeded.AuthEventReferences: %w", err)
	}

	input.EventTemplate.AuthEvents, input.EventTemplate.PrevEvents = truncateAuthAndPrevEvents(refs, latestEvents.PrevEventIDs)

	checkEventAllowed := func(inviteEvent PDU) error {
		// The invite originated locally. Therefore we have a responsibility to
		// try and see if the user is allowed to make this invite. We can't do
		// this for invites coming in over federation - we have to take those on
		// trust.
		authEventProvider, err := input.StateQuerier.GetAuthEvents(ctx, inviteEvent)
		if err != nil {
			logger.WithError(err).WithField("event_id", inviteEvent.EventID()).WithField("auth_event_ids", inviteEvent.AuthEventIDs()).Error(
				"ProcessInvite.getAuthEvents failed for event",
			)
			return spec.Forbidden(err.Error())
		}

		// Check if the event is allowed.
		if err = Allowed(inviteEvent, authEventProvider, input.UserIDQuerier); err != nil {
			logger.WithError(err).WithField("event_id", inviteEvent.EventID()).WithField("auth_event_ids", inviteEvent.AuthEventIDs()).Error(
				"ProcessInvite: event not allowed",
			)
			return spec.Forbidden(err.Error())
		}

		return nil
	}

	// If the target isn't local then we should send the invite
	// over federation. It might be that the remote user doesn't exist,
	// in which case we can give up processing here.
	var inviteEvent PDU
	switch input.FrameVersion {
	case FrameVersionPseudoIDs:
		keyID := KeyID("ed25519:1")
		origin := spec.ServerName(spec.SenderIDFromPseudoIDKey(input.SigningKey))

		if input.IsTargetLocal {
			// if we invited a local user, we can also create a user frame key, if it doesn't exist yet.
			inviteeSenderID, inviteeSigningKey, err := input.SenderIDCreator(ctx, input.Invitee, input.FrameID, string(input.FrameVersion))
			if err != nil {
				return nil, err
			}

			inviteeSenderIDString := string(inviteeSenderID)
			input.EventTemplate.StateKey = &inviteeSenderIDString

			// Sign the event so that other servers will know that we have received the invite.
			fullEventBuilder := verImpl.NewEventBuilderFromProtoEvent(&input.EventTemplate)
			inviteEvent, err = fullEventBuilder.Build(input.EventTime, spec.ServerName(inviteeSenderID), keyID, inviteeSigningKey)
			if err != nil {
				logger.WithError(err).Error("failed building invite event")
				return nil, spec.InternalServerError{}
			}

			// Have the inviter also sign the event
			inviteEvent = inviteEvent.Sign(string(origin), keyID, input.SigningKey)

			verifier := JSONVerifierSelf{}
			err = VerifyEventSignatures(ctx, inviteEvent, verifier, input.UserIDQuerier)
			if err != nil {
				logger.WithError(err).Error("local invite event has invalid signatures")
				return nil, spec.Forbidden(err.Error())
			}

			err = checkEventAllowed(inviteEvent)
			if err != nil {
				return nil, err
			}
		} else {
			inviteEvent, err = fedClient.SendInviteV3(ctx, input.EventTemplate, input.Invitee, input.FrameVersion, inviteState)
			if err != nil {
				logger.WithError(err).Error("fedClient.SendInviteV3 failed")
				return nil, spec.Forbidden(err.Error())
			}
			logger.Debugf("Federated SendInviteV3 success to user %s", input.Invitee.String())

			// Have the inviter also sign the event
			inviteEvent = inviteEvent.Sign(
				string(origin), keyID, input.SigningKey,
			)

			verifier := JSONVerifierSelf{}
			err := VerifyEventSignatures(ctx, inviteEvent, verifier, input.UserIDQuerier)
			if err != nil {
				logger.WithError(err).Error("fedClient.SendInviteV3 returned event with invalid signatures")
				return nil, spec.Forbidden(err.Error())
			}

			err = input.StoreSenderIDFromPublicID(ctx, spec.SenderID(*inviteEvent.StateKey()), input.Invitee.String(), input.FrameID)
			if err != nil {
				logger.WithError(err).Errorf("failed storing senderID for %s", input.Invitee.String())
				return nil, spec.InternalServerError{}
			}

			// TODO: This should happen before the federation call ideally,
			// but we don't have a full PDU yet in this case by that point.
			err = checkEventAllowed(inviteEvent)
			if err != nil {
				return nil, err
			}
		}
	default:
		inviteeSenderID := input.Invitee.String()
		input.EventTemplate.StateKey = &inviteeSenderID

		// Sign the event so that other servers will know that we have received the invite.
		fullEventBuilder := verImpl.NewEventBuilderFromProtoEvent(&input.EventTemplate)
		fullEvent, err := fullEventBuilder.Build(input.EventTime, input.Inviter.Domain(), input.KeyID, input.SigningKey)
		if err != nil {
			logger.WithError(err).Error("failed building invite event")
			return nil, spec.InternalServerError{}
		}

		inviteEvent = fullEvent.Sign(
			string(input.Invitee.Domain()), input.KeyID, input.SigningKey,
		)

		err = checkEventAllowed(inviteEvent)
		if err != nil {
			return nil, err
		}

		if !input.IsTargetLocal {
			eventID := inviteEvent.EventID()
			inviteEvent, err = fedClient.SendInvite(ctx, inviteEvent, inviteState)
			if err != nil {
				logger.WithError(err).WithField("event_id", eventID).Error("fedClient.SendInvite failed")
				return nil, spec.Forbidden(err.Error())
			}
			logger.Debugf("Federated SendInvite success with event ID %s", eventID)
		}
	}

	return inviteEvent, nil
}

// truncateAuthAndPrevEvents limits the number of events we add into
// an event as prev_events or auth_events.
// NOTSPEC: The limits here feel a bit arbitrary but they are currently
// here because of https://github.com/coddy-org/coddy-doc/issues/2307
// and because Synapse will just drop events that don't comply.
func truncateAuthAndPrevEvents(auth, prev []string) (
	truncAuth, truncPrev []string,
) {
	truncAuth, truncPrev = auth, prev
	if len(truncAuth) > 10 {
		truncAuth = truncAuth[:10]
	}
	if len(truncPrev) > 20 {
		truncPrev = truncPrev[:20]
	}
	return
}
