package fclient

import (
	"encoding/json"

	"github.com/withqb/xtools"
)

func NewInviteV3Request(event xtools.ProtoEvent, version xtools.RoomVersion, state []xtools.InviteStrippedState) (
	request InviteV3Request, err error,
) {
	if !xtools.KnownRoomVersion(version) {
		err = xtools.UnsupportedRoomVersionError{
			Version: version,
		}
		return
	}
	request.fields.inviteV2RequestHeaders = inviteV2RequestHeaders{
		RoomVersion:     version,
		InviteRoomState: state,
	}
	request.fields.Event = event
	return
}

// InviteV3Request is used in the body of a /_matrix/federation/v3/invite request.
type InviteV3Request struct {
	fields struct {
		inviteV2RequestHeaders
		Event xtools.ProtoEvent `json:"event"`
	}
}

// MarshalJSON implements json.Marshaller
func (i InviteV3Request) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.fields)
}

// UnmarshalJSON implements json.Unmarshaller
func (i *InviteV3Request) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &i.fields)
	if err != nil {
		return err
	}
	return err
}

// Event returns the invite event.
func (i *InviteV3Request) Event() xtools.ProtoEvent {
	return i.fields.Event
}

// RoomVersion returns the room version of the invited room.
func (i *InviteV3Request) RoomVersion() xtools.RoomVersion {
	return i.fields.RoomVersion
}

// InviteRoomState returns stripped state events for the room, containing
// enough information for the client to identify the room.
func (i *InviteV3Request) InviteRoomState() []xtools.InviteStrippedState {
	return i.fields.InviteRoomState
}
