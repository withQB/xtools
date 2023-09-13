package fclient

import (
	"encoding/json"
	"errors"

	"github.com/tidwall/gjson"
	"github.com/withqb/xtools"
)

// InviteV2Request and InviteV2StrippedState are defined in

func NewInviteV2Request(event xtools.PDU, state []xtools.InviteStrippedState) (
	request InviteV2Request, err error,
) {
	if !xtools.KnownFrameVersion(event.Version()) {
		err = xtools.UnsupportedFrameVersionError{
			Version: event.Version(),
		}
		return
	}
	request.fields.inviteV2RequestHeaders = inviteV2RequestHeaders{
		FrameVersion:     event.Version(),
		InviteFrameState: state,
	}
	request.fields.Event = event
	return
}

type inviteV2RequestHeaders struct {
	FrameVersion     xtools.FrameVersion           `json:"frame_version"`
	InviteFrameState []xtools.InviteStrippedState `json:"invite_frame_state"`
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
	verImpl, err := xtools.GetFrameVersion(i.fields.FrameVersion)
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

// FrameVersion returns the frame version of the invited frame.
func (i *InviteV2Request) FrameVersion() xtools.FrameVersion {
	return i.fields.FrameVersion
}

// InviteFrameState returns stripped state events for the frame, containing
// enough information for the client to identify the frame.
func (i *InviteV2Request) InviteFrameState() []xtools.InviteStrippedState {
	return i.fields.InviteFrameState
}
