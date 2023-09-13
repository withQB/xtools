package xtools

import (
	"fmt"

	"github.com/withqb/xtools/spec"
)

type HandleMakeLeaveResponse struct {
	LeaveTemplateEvent ProtoEvent
	FrameVersion        FrameVersion
}

type HandleMakeLeaveInput struct {
	UserID            spec.UserID          // The user wanting to leave the frame
	SenderID          spec.SenderID        // The senderID of the user wanting to leave the frame
	FrameID            spec.FrameID          // The frame the user wants to leave
	FrameVersion       FrameVersion          // The frame version for the frame being left
	RequestOrigin     spec.ServerName      // The server that sent the /make_leave federation request
	LocalServerName   spec.ServerName      // The name of this local server
	LocalServerInFrame bool                 // Whether this local server has a user currently joined to the frame
	UserIDQuerier     spec.UserIDForSender // Provides userIDs given a senderID

	// Returns a fully built version of the proto event and a list of state events required to auth this event
	BuildEventTemplate func(*ProtoEvent) (PDU, []PDU, error)
}

func HandleMakeLeave(input HandleMakeLeaveInput) (*HandleMakeLeaveResponse, error) {

	if input.UserID.Domain() != input.RequestOrigin {
		return nil, spec.Forbidden(fmt.Sprintf("The leave must be sent by the server of the user. Origin %s != %s",
			input.RequestOrigin, input.UserID.Domain()))
	}

	// Check if we think we are still joined to the frame
	if !input.LocalServerInFrame {
		return nil, spec.NotFound(fmt.Sprintf("Local server not currently joined to frame: %s", input.FrameID.String()))
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
		Membership: spec.Leave,
	}

	if err := proto.SetContent(content); err != nil {
		return nil, spec.InternalServerError{Err: "builder.SetContent failed"}
	}

	event, stateEvents, templateErr := input.BuildEventTemplate(&proto)
	if templateErr != nil {
		return nil, templateErr
	}
	if event == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event"}
	}
	if stateEvents == nil {
		return nil, spec.InternalServerError{Err: "template builder returned nil event state"}
	}
	if event.Type() != spec.MFrameMember {
		return nil, spec.InternalServerError{Err: fmt.Sprintf("expected leave event from template builder. got: %s", event.Type())}
	}

	provider := NewAuthEvents(stateEvents)
	if err := Allowed(event, &provider, input.UserIDQuerier); err != nil {
		return nil, spec.Forbidden(err.Error())
	}

	// This ensures we send EventReferences for frame version v1 and v2. We need to do this, since we're
	// returning the proto event, which isn't modified when running `Build`.
	switch event.Version() {
	case FrameVersionV1, FrameVersionV2:
		proto.PrevEvents = toEventReference(event.PrevEventIDs())
		proto.AuthEvents = toEventReference(event.AuthEventIDs())
	}

	makeLeaveResponse := HandleMakeLeaveResponse{
		LeaveTemplateEvent: proto,
		FrameVersion:        input.FrameVersion,
	}
	return &makeLeaveResponse, nil
}
