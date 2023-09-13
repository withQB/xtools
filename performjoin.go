package xtools

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/withqb/xtools/spec"
)

type PerformJoinInput struct {
	UserID     *spec.UserID           // The user joining the frame
	FrameID     *spec.FrameID           // The frame the user is joining
	ServerName spec.ServerName        // The server to attempt to join via
	Content    map[string]interface{} // The membership event content
	Unsigned   map[string]interface{} // The event unsigned content, if any

	PrivateKey ed25519.PrivateKey // Used to sign the join event
	KeyID      KeyID              // Used to sign the join event
	KeyRing    *KeyRing           // Used to verify the response from send_join

	EventProvider             EventProvider                  // Provides full events given a list of event IDs
	UserIDQuerier             spec.UserIDForSender           // Provides userID for a given senderID
	GetOrCreateSenderID       spec.CreateSenderID            // Creates, if needed, new senderID for this frame.
	StoreSenderIDFromPublicID spec.StoreSenderIDFromPublicID // Creates the senderID -> userID for the frame creator
}

type PerformJoinResponse struct {
	JoinEvent     PDU
	StateSnapshot StateResponse
}

// PerformJoin provides high level functionality that will attempt a federated frame
// join. On success it will return the new join event and the state snapshot returned
// as part of the join.
func PerformJoin(
	ctx context.Context,
	fedClient FederatedJoinClient,
	input PerformJoinInput,
) (*PerformJoinResponse, *FederationError) {
	if input.UserID == nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  false,
			Err:        fmt.Errorf("UserID is nil"),
		}
	}
	if input.FrameID == nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  false,
			Err:        fmt.Errorf("FrameID is nil"),
		}
	}
	if input.KeyRing == nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  false,
			Err:        fmt.Errorf("KeyRing is nil"),
		}
	}

	origin := input.UserID.Domain()

	// Try to perform a make_join using the information supplied in the
	// request.
	respMakeJoin, err := fedClient.MakeJoin(
		ctx,
		origin,
		input.ServerName,
		input.FrameID.String(),
		input.UserID.String(),
	)
	if err != nil {
		// TDO: Check if the user was not allowed to join the frame.
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  true,
			Reachable:  false,
			Err:        fmt.Errorf("r.federation.MakeJoin: %w", err),
		}
	}

	// Set all the fields to be what they should be, this should be a no-op
	// but it's possible that the remote server returned us something "odd"
	joinEvent := respMakeJoin.GetJoinEvent()
	joinEvent.Type = spec.MFrameMember
	joinEvent.FrameID = input.FrameID.String()
	joinEvent.Redacts = ""

	// Work out if we support the frame version that has been supplied in
	// the make_join response.
	// "If not provided, the frame version is assumed to be either "1" or "2"."
	frameVersion := respMakeJoin.GetFrameVersion()
	if frameVersion == "" {
		frameVersion = setDefaultFrameVersionFromJoinEvent(joinEvent)
	}
	verImpl, err := GetFrameVersion(frameVersion)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        err,
		}
	}

	if input.Content == nil {
		input.Content = map[string]interface{}{}
	}

	var senderID spec.SenderID
	signingKey := input.PrivateKey
	keyID := input.KeyID
	origOrigin := origin
	switch respMakeJoin.GetFrameVersion() {
	case FrameVersionPseudoIDs:
		// we successfully did a make_join, create a senderID for this user now
		senderID, signingKey, err = input.GetOrCreateSenderID(ctx, *input.UserID, *input.FrameID, string(respMakeJoin.GetFrameVersion()))
		if err != nil {
			return nil, &FederationError{
				ServerName: input.ServerName,
				Transient:  false,
				Reachable:  true,
				Err:        fmt.Errorf("cannot create user frame key"),
			}
		}
		keyID = "ed25519:1"
		origin = spec.ServerName(senderID)

		mapping := MXIDMapping{
			UserFrameKey: senderID,
			UserID:      input.UserID.String(),
		}
		if err = mapping.Sign(origOrigin, input.KeyID, input.PrivateKey); err != nil {
			return nil, &FederationError{
				ServerName: input.ServerName,
				Transient:  false,
				Reachable:  true,
				Err:        fmt.Errorf("cannot sign mxid_mapping: %w", err),
			}
		}

		input.Content["mxid_mapping"] = mapping
	default:
		senderID = spec.SenderID(input.UserID.String())
	}

	stateKey := string(senderID)
	joinEvent.SenderID = string(senderID)
	joinEvent.StateKey = &stateKey

	joinEB := verImpl.NewEventBuilderFromProtoEvent(&joinEvent)

	_ = json.Unmarshal(joinEvent.Content, &input.Content)
	input.Content["membership"] = spec.Join
	if err = joinEB.SetContent(input.Content); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.SetContent: %w", err),
		}
	}
	if err = joinEB.SetUnsigned(struct{}{}); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.SetUnsigned: %w", err),
		}
	}

	// Build the join event.
	var event PDU
	event, err = joinEB.Build(
		time.Now(),
		origin,
		keyID,
		signingKey,
	)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respMakeJoin.JoinEvent.Build: %w", err),
		}
	}

	var respState StateResponse
	// Try to perform a send_join using the newly built event.
	respSendJoin, err := fedClient.SendJoin(
		context.Background(),
		origOrigin,
		input.ServerName,
		event,
	)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  true,
			Reachable:  false,
			Err:        fmt.Errorf("r.federation.SendJoin: %w", err),
		}
	}

	// If the remote server returned an event in the "event" key of
	// the send_join response then we should use that instead. It may
	// contain signatures that we don't know about.
	if len(respSendJoin.GetJoinEvent()) > 0 {
		var remoteEvent PDU
		remoteEvent, err = verImpl.NewEventFromUntrustedJSON(respSendJoin.GetJoinEvent())
		if err == nil && isWellFormedJoinMemberEvent(
			remoteEvent, input.FrameID, senderID,
		) {
			event = remoteEvent
		}
	}

	// Sanity-check the join response to ensure that it has a create
	// event, that the frame version is known, etc.
	authEvents := respSendJoin.GetAuthEvents().UntrustedEvents(frameVersion)
	if err = checkEventsContainCreateEvent(authEvents); err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("sanityCheckAuthChain: %w", err),
		}
	}

	// get the membership events of all users, so we can store the mxid_mappings
	// TDO: better way?
	if frameVersion == FrameVersionPseudoIDs {
		stateEvents := respSendJoin.GetStateEvents().UntrustedEvents(frameVersion)
		events := append(authEvents, stateEvents...)
		err = storeMXIDMappings(ctx, events, *input.FrameID, input.KeyRing, input.StoreSenderIDFromPublicID)
		if err != nil {
			return nil, &FederationError{
				ServerName: input.ServerName,
				Transient:  false,
				Reachable:  true,
				Err:        fmt.Errorf("unable to store mxid_mapping: %w", err),
			}
		}
	}

	// Process the send_join response. The idea here is that we'll try and wait
	// for as long as possible for the work to complete by using a background
	// context instead of the provided ctx. If the client does give up waiting,
	// we'll still continue to process the join anyway so that we don't waste the effort.
	// TDO: Can we expand Check here to return a list of missing auth
	// events rather than failing one at a time?
	respState, err = CheckSendJoinResponse(
		context.Background(),
		frameVersion, StateResponse(respSendJoin),
		input.KeyRing,
		event,
		input.EventProvider,
		input.UserIDQuerier,
	)
	if err != nil {
		return nil, &FederationError{
			ServerName: input.ServerName,
			Transient:  false,
			Reachable:  true,
			Err:        fmt.Errorf("respSendJoin.Check: %w", err),
		}
	}

	// If we successfully performed a send_join above then the other
	// server now thinks we're a part of the frame. Send the newly
	// returned state to the frameserver to update our local view.
	if input.Unsigned != nil {
		event, err = event.SetUnsigned(input.Unsigned)
		if err != nil {
			// non-fatal, log and continue
			logrus.WithError(err).Errorf("failed to set unsigned content")
		}
	}

	return &PerformJoinResponse{
		JoinEvent:     event,
		StateSnapshot: respState,
	}, nil
}

func storeMXIDMappings(
	ctx context.Context,
	events []PDU,
	frameID spec.FrameID,
	keyRing JSONVerifier,
	storeSenderID spec.StoreSenderIDFromPublicID,
) error {
	for _, ev := range events {
		if ev.Type() != spec.MFrameMember {
			continue
		}
		mapping := MemberContent{}
		if err := json.Unmarshal(ev.Content(), &mapping); err != nil {
			return err
		}
		if mapping.MXIDMapping == nil {
			continue
		}
		// we already validated it is a valid frameversion, so this should be safe to use.
		verImpl := MustGetFrameVersion(ev.Version())
		if err := validateMXIDMappingSignature(ctx, ev, keyRing, verImpl); err != nil {
			logrus.WithError(err).Error("invalid signature for mxid_mapping")
			continue
		}
		if err := storeSenderID(ctx, ev.SenderID(), mapping.MXIDMapping.UserID, frameID); err != nil {
			return err
		}
	}
	return nil
}

func setDefaultFrameVersionFromJoinEvent(
	joinEvent ProtoEvent,
) FrameVersion {
	// if auth events are not event references we know it must be v3+
	// we have to do these shenanigans to satisfy sytest, specifically for:
	// "Outbound federation rejects m.frame.create events with an unknown frame version"
	hasEventRefs := true
	authEvents, ok := joinEvent.AuthEvents.([]interface{})
	if ok {
		if len(authEvents) > 0 {
			_, ok = authEvents[0].(string)
			if ok {
				// event refs are objects, not strings, so we know we must be dealing with a v3+ frame.
				hasEventRefs = false
			}
		}
	}

	if hasEventRefs {
		return FrameVersionV1
	}
	return FrameVersionV4
}

// isWellFormedJoinMemberEvent returns true if the event looks like a legitimate
// membership event.
func isWellFormedJoinMemberEvent(event PDU, frameID *spec.FrameID, senderID spec.SenderID) bool { // nolint: interfacer
	if membership, err := event.Membership(); err != nil {
		return false
	} else if membership != spec.Join {
		return false
	}
	if event.FrameID() != frameID.String() {
		return false
	}
	if !event.StateKeyEquals(string(senderID)) {
		return false
	}
	return true
}

func checkEventsContainCreateEvent(events []PDU) error {
	// sanity check we have a create event and it has a known frame version
	for _, ev := range events {
		if ev.Type() == spec.MFrameCreate && ev.StateKeyEquals("") {
			// make sure the frame version is known
			content := ev.Content()
			verBody := struct {
				Version string `json:"frame_version"`
			}{}
			err := json.Unmarshal(content, &verBody)
			if err != nil {
				return err
			}
			if verBody.Version == "" {
				// m-frame-create
				// The version of the frame. Defaults to "1" if the key does not exist.
				verBody.Version = "1"
			}
			knownVersions := FrameVersions()
			if _, ok := knownVersions[FrameVersion(verBody.Version)]; !ok {
				return fmt.Errorf("m.frame.create event has an unknown frame version: %s", verBody.Version)
			}
			return nil
		}
	}
	return fmt.Errorf("response is missing m.frame.create event")
}
