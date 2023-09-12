package fclient

import (
	"encoding/json"
	"errors"

	"github.com/tidwall/gjson"
	"github.com/withqb/xtools"
)

// InviteV2Request and InviteV2StrippedState are defined in
// https://matrix.org/docs/spec/server_server/r0.1.3#put-matrix-federation-v2-invite-roomid-eventid

func NewInviteV2Request(event xtools.PDU, state []xtools.InviteStrippedState) (
	request InviteV2Request, err error,
) {
	if !xtools.KnownRoomVersion(event.Version()) {
		err = xtools.UnsupportedRoomVersionError{
			Version: event.Version(),
		}
		return
	}
	request.fields.inviteV2RequestHeaders = inviteV2RequestHeaders{
		RoomVersion:     event.Version(),
		InviteRoomState: state,
	}
	request.fields.Event = event
	return
}

type inviteV2RequestHeaders struct {
	RoomVersion     xtools.RoomVersion           `json:"room_version"`
	InviteRoomState []xtools.InviteStrippedState `json:"invite_room_state"`
}

// InviteV2Request is used in the body of a /_matrix/federation/v2/invite request.
type InviteV2Request struct {
	fields struct {
		inviteV2RequestHeaders
		Event xtools.PDU `json:"event"`
	}
}

// MarshalJSON implements json.Marshaller
func (i InviteV2Request) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteV2Request) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &i.fields.inviteV2RequestHeaders)
	if err != nil {
		return err
	}
	eventJSON := gjson.GetBytes(data, "event")
	if !eventJSON.Exists() {
		return errors.New("xtools: request doesn't contain event")
	}
	verImpl, err := xtools.GetRoomVersion(i.fields.RoomVersion)
	if err != nil {
		return err
	}
	i.fields.Event, err = verImpl.NewEventFromUntrustedJSON([]byte(eventJSON.String()))
	return err
}

// Event returns the invite event.
func (i *InviteV2Request) Event() xtools.PDU {
	return i.fields.Event
}

// RoomVersion returns the room version of the invited room.
func (i *InviteV2Request) RoomVersion() xtools.RoomVersion {
	return i.fields.RoomVersion
}

// InviteRoomState returns stripped state events for the room, containing
// enough information for the client to identify the room.
func (i *InviteV2Request) InviteRoomState() []xtools.InviteStrippedState {
	return i.fields.InviteRoomState
}
