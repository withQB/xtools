package fclient

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"

	"github.com/tidwall/gjson"
	"github.com/withqb/xtools"
	"github.com/withqb/xtools/spec"
)

// A RespSend is the content of a response to PUT /_coddy/federation/v1/send/{txnID}/
type RespSend struct {
	// Map of event ID to the result of processing that event.
	PDUs map[string]PDUResult `json:"pdus"`
}

// A PDUResult is the result of processing a coddy frame event.
type PDUResult struct {
	// If not empty then this is a human readable description of a problem
	// encountered processing an event.
	Error string `json:"error,omitempty"`
}

// A RespStateIDs is the content of a response to GET /_coddy/federation/v1/state_ids/{frameID}/{eventID}
type RespStateIDs struct {
	// A list of state event IDs for the state of the frame before the requested event.
	StateEventIDs []string `json:"pdu_ids"`
	// A list of event IDs needed to authenticate the state events.
	AuthEventIDs []string `json:"auth_chain_ids"`
}

func (r RespStateIDs) GetStateEventIDs() []string {
	return r.StateEventIDs
}

func (r RespStateIDs) GetAuthEventIDs() []string {
	return r.AuthEventIDs
}

// A RespState is the content of a response to GET /_coddy/federation/v1/state/{frameID}/{eventID}
type RespState struct {
	// A list of events giving the state of the frame before the request event.
	StateEvents xtools.EventJSONs `json:"pdus"`
	// A list of events needed to authenticate the state events.
	AuthEvents xtools.EventJSONs `json:"auth_chain"`
}

func (r *RespState) GetStateEvents() xtools.EventJSONs {
	return r.StateEvents
}

func (r *RespState) GetAuthEvents() xtools.EventJSONs {
	return r.AuthEvents
}

// A RespPeek is the content of a response to GET /_coddy/federation/v1/peek/{frameID}/{peekID}
type RespPeek struct {
	// How often should we renew the peek?
	RenewalInterval int64 `json:"renewal_interval"`
	// A list of events giving the state of the frame at the point of the request
	StateEvents xtools.EventJSONs `json:"state"`
	// A list of events needed to authenticate the state events.
	AuthEvents xtools.EventJSONs `json:"auth_chain"`
	// The frame version that we're trying to peek.
	FrameVersion xtools.FrameVersion `json:"frame_version"`
	// The ID of the event whose state snapshot this is - i.e. the
	// most recent forward extremity in the frame.
	LatestEvent xtools.PDU `json:"latest_event"`
}

func (r *RespPeek) GetStateEvents() xtools.EventJSONs {
	return r.StateEvents
}

func (r *RespPeek) GetAuthEvents() xtools.EventJSONs {
	return r.AuthEvents
}

// MissingEvents represents a request for missing events.
type MissingEvents struct {
	// The maximum number of events to retrieve.
	Limit int `json:"limit"`
	// The minimum depth of events to retrieve.
	MinDepth int `json:"min_depth"`
	// The latest event IDs that the sender already has.
	EarliestEvents []string `json:"earliest_events"`
	// The event IDs to retrieve the previous events for.
	LatestEvents []string `json:"latest_events"`
}

// A RespMissingEvents is the content of a response to GET /_coddy/federation/v1/get_missing_events/{frameID}
type RespMissingEvents struct {
	// The returned set of missing events.
	Events xtools.EventJSONs `json:"events"`
}

// RespPublicFrames is the content of a response to GET /_coddy/federation/v1/publicFrames
type RespPublicFrames struct {
	// A paginated chunk of public frames.
	Chunk []PublicFrame `json:"chunk"`
	// A pagination token for the response. The absence of this token means there are no more results to fetch and the client should stop paginating.
	NextBatch string `json:"next_batch,omitempty"`
	// A pagination token that allows fetching previous results. The absence of this token means there are no results before this batch, i.e. this is the first batch.
	PrevBatch string `json:"prev_batch,omitempty"`
	// An estimate on the total number of public frames, if the server has an estimate.
	TotalFrameCountEstimate int `json:"total_frame_count_estimate,omitempty"`
}

// PublicFrame stores the info of a frame returned by
// GET /_coddy/federation/v1/publicFrames
type PublicFrame struct {
	// Aliases of the frame. May be empty.
	Aliases []string `json:"aliases,omitempty"`
	// The canonical alias of the frame, if any.
	CanonicalAlias string `json:"canonical_alias,omitempty"`
	// The name of the frame, if any.
	Name string `json:"name,omitempty"`
	// The number of members joined to the frame.
	JoinedMembersCount int `json:"num_joined_members"`
	// The ID of the frame.
	FrameID string `json:"frame_id"`
	// The topic of the frame, if any.
	Topic string `json:"topic,omitempty"`
	// Whether the frame may be viewed by guest users without joining.
	WorldReadable bool `json:"world_readable"`
	// Whether guest users may join the frame and participate in it. If they can, they will be subject to ordinary power level rules like any other user.
	GuestCanJoin bool `json:"guest_can_join"`
	// The URL for the frame's avatar, if one is set.
	AvatarURL string `json:"avatar_url,omitempty"`
}

// A RespEventAuth is the content of a response to GET /_coddy/federation/v1/event_auth/{frameID}/{eventID}
type RespEventAuth struct {
	// A list of events needed to authenticate the state events.
	AuthEvents xtools.EventJSONs `json:"auth_chain"`
}

type respStateFields struct {
	StateEvents xtools.EventJSONs `json:"pdus"`
	AuthEvents  xtools.EventJSONs `json:"auth_chain"`
}

// RespUserDevices contains a response to /_coddy/federation/v1/user/devices/{userID}
// get-coddy-federation-v1-user-devices-userid
type RespUserDevices struct {
	UserID         string           `json:"user_id"`
	StreamID       int64            `json:"stream_id"`
	Devices        []RespUserDevice `json:"devices"`
	MasterKey      *CrossSigningKey `json:"master_key"`
	SelfSigningKey *CrossSigningKey `json:"self_signing_key"`
}

type EmptyResp struct {
}

// UnmarshalJSON is used here because people on Synapses can apparently upload
// nonsense into their device keys in types that don't match the expected and
// that can cause the entire response to fail to unmarshal. This simply skips
// anything that fails to unmarshal and returns the rest.
func (r *RespUserDevices) UnmarshalJSON(data []byte) error {
	intermediate := struct {
		UserID         string            `json:"user_id"`
		StreamID       int64             `json:"stream_id"`
		Devices        []json.RawMessage `json:"devices"`
		MasterKey      json.RawMessage   `json:"master_key"`
		SelfSigningKey json.RawMessage   `json:"self_signing_key"`
	}{}
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}
	r.UserID = intermediate.UserID
	r.StreamID = intermediate.StreamID
	_ = json.Unmarshal(intermediate.MasterKey, &r.MasterKey)
	_ = json.Unmarshal(intermediate.SelfSigningKey, &r.SelfSigningKey)
	for _, deviceJSON := range intermediate.Devices {
		var device RespUserDevice
		if err := json.Unmarshal(deviceJSON, &device); err == nil {
			r.Devices = append(r.Devices, device)
		}
	}
	return nil
}

// RespUserDevice are embedded in RespUserDevices
// get-coddy-federation-v1-user-devices-userid
type RespUserDevice struct {
	DeviceID    string             `json:"device_id"`
	DisplayName string             `json:"device_display_name"`
	Keys        RespUserDeviceKeys `json:"keys"`
}

// RespUserDeviceKeys are embedded in RespUserDevice
// get-coddy-federation-v1-user-devices-userid
type RespUserDeviceKeys struct {
	UserID     string   `json:"user_id"`
	DeviceID   string   `json:"device_id"`
	Algorithms []string `json:"algorithms"`
	// E.g "curve25519:JLAFKJWSCS": "3C5BFWi2Y8MaVvjM8M22DBmh24PmgR0nPvJOIArzgyI"
	Keys map[xtools.KeyID]spec.Base64Bytes `json:"keys"`
	// E.g "@alice:example.com": {
	//	"ed25519:JLAFKJWSCS": "dSO80A01XiigH3uBiDVx/EjzaoycHcjq9lfQX0uWsqxl2giMIiSPR8a4d291W1ihKJL/a+myXS367WT6NAIcBA"
	// }
	Signatures map[string]map[xtools.KeyID]spec.Base64Bytes `json:"signatures"`
}

// MarshalJSON implements json.Marshaller
func (r RespPeek) MarshalJSON() ([]byte, error) {
	if len(r.StateEvents) == 0 {
		r.StateEvents = xtools.EventJSONs{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = xtools.EventJSONs{}
	}
	return json.Marshal(struct {
		RenewalInterval int64              `json:"renewal_interval"`
		StateEvents     xtools.EventJSONs  `json:"state"`
		AuthEvents      xtools.EventJSONs  `json:"auth_chain"`
		FrameVersion     xtools.FrameVersion `json:"frame_version"`
		LatestEvent     xtools.PDU         `json:"latest_event"`
	}{
		RenewalInterval: r.RenewalInterval,
		StateEvents:     r.StateEvents,
		AuthEvents:      r.AuthEvents,
		FrameVersion:     r.FrameVersion,
		LatestEvent:     r.LatestEvent,
	})
}

// MarshalJSON implements json.Marshaller
func (r RespState) MarshalJSON() ([]byte, error) {
	if len(r.StateEvents) == 0 {
		r.StateEvents = xtools.EventJSONs{}
	}
	if len(r.AuthEvents) == 0 {
		r.AuthEvents = xtools.EventJSONs{}
	}
	return json.Marshal(respStateFields{ // nolint:gosimple
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
	})
}

// A RespMakeJoin is the content of a response to GET /_coddy/federation/v2/make_join/{frameID}/{userID}
type RespMakeJoin struct {
	// An incomplete m.frame.member event for a user on the requesting server
	// generated by the responding server.
	JoinEvent   xtools.ProtoEvent  `json:"event"`
	FrameVersion xtools.FrameVersion `json:"frame_version"`
}

func (r *RespMakeJoin) GetJoinEvent() xtools.ProtoEvent {
	return r.JoinEvent
}

func (r *RespMakeJoin) GetFrameVersion() xtools.FrameVersion {
	return r.FrameVersion
}

// A RespSendJoin is the content of a response to PUT /_coddy/federation/v2/send_join/{frameID}/{eventID}
type RespSendJoin struct {
	// A list of events giving the state of the frame before the request event.
	StateEvents xtools.EventJSONs `json:"state"`
	// A list of events needed to authenticate the state events.
	AuthEvents xtools.EventJSONs `json:"auth_chain"`
	// The server that originated the event.
	Origin spec.ServerName `json:"origin"`
	// The returned join event from the remote server. Used for restricted joins,
	// but not guaranteed to be present as it's only since MSC3083.
	Event spec.RawJSON `json:"event,omitempty"`
	// true if the state is incomplete
	MembersOmitted bool `json:"members_omitted"`
	// a list of servers in the frame. Only returned if partial_state is set.
	ServersInFrame []string `json:"servers_in_frame"`
}

func (r *RespSendJoin) GetStateEvents() xtools.EventJSONs {
	return r.StateEvents
}

func (r *RespSendJoin) GetAuthEvents() xtools.EventJSONs {
	return r.AuthEvents
}

func (r *RespSendJoin) GetOrigin() spec.ServerName {
	return r.Origin
}

func (r *RespSendJoin) GetJoinEvent() spec.RawJSON {
	return r.Event
}

func (r *RespSendJoin) GetMembersOmitted() bool {
	return r.MembersOmitted
}

func (r *RespSendJoin) GetServersInFrame() []string {
	return r.ServersInFrame
}

// MarshalJSON implements json.Marshaller
func (r RespSendJoin) MarshalJSON() ([]byte, error) {
	fields := respSendJoinFields{
		StateEvents: r.StateEvents,
		AuthEvents:  r.AuthEvents,
		Origin:      r.Origin,
		Event:       r.Event,
	}
	if len(fields.AuthEvents) == 0 {
		fields.AuthEvents = xtools.EventJSONs{}
	}
	if len(fields.StateEvents) == 0 {
		fields.StateEvents = xtools.EventJSONs{}
	}

	if !r.MembersOmitted {
		return json.Marshal(fields)
	}

	partialJoinFields := respSendJoinPartialStateFields{
		respSendJoinFields: fields,
		MembersOmitted:     true,
		ServersInFrame:      r.ServersInFrame,
	}
	return json.Marshal(partialJoinFields)
}

// A RespSendKnock is the content of a response to PUT /_coddy/federation/v2/send_knock/{frameID}/{eventID}
type RespSendKnock struct {
	// A list of stripped state events to help the initiator of the knock identify the frame.
	KnockFrameState []xtools.InviteStrippedState `json:"knock_frame_state"`
}

// A RespMakeKnock is the content of a response to GET /_coddy/federation/v2/make_knock/{frameID}/{userID}
type RespMakeKnock struct {
	// An incomplete m.frame.member event for a user on the requesting server
	// generated by the responding server.
	KnockEvent  xtools.ProtoEvent  `json:"event"`
	FrameVersion xtools.FrameVersion `json:"frame_version"`
}

// respSendJoinFields is an intermediate struct used in RespSendJoin.MarshalJSON
type respSendJoinFields struct {
	StateEvents xtools.EventJSONs `json:"state"`
	AuthEvents  xtools.EventJSONs `json:"auth_chain"`
	Origin      spec.ServerName   `json:"origin"`
	Event       spec.RawJSON      `json:"event,omitempty"`
}

// respSendJoinPartialStateFields extends respSendJoinFields with the fields added
// when the response has incomplete state.
type respSendJoinPartialStateFields struct {
	respSendJoinFields
	MembersOmitted bool     `json:"members_omitted"`
	ServersInFrame  []string `json:"servers_in_frame"`
}

// A RespMakeLeave is the content of a response to GET /_coddy/federation/v2/make_leave/{frameID}/{userID}
type RespMakeLeave struct {
	// An incomplete m.frame.member event for a user on the requesting server
	// generated by the responding server.
	LeaveEvent xtools.ProtoEvent `json:"event"`
	// The frame version that we're trying to leave.
	FrameVersion xtools.FrameVersion `json:"frame_version"`
}

// A RespDirectory is the content of a response to GET  /_coddy/federation/v1/query/directory
// This is returned when looking up a frame alias from a remote server.
type RespDirectory struct {
	// The coddy frame ID the frame alias corresponds to.
	FrameID string `json:"frame_id"`
	// A list of coddy servers that the directory server thinks could be used
	// to join the frame. The joining server may need to try multiple servers
	// before it finds one that it can use to join the frame.
	Servers []spec.ServerName `json:"servers"`
}

// RespProfile is the content of a response to GET /_coddy/federation/v1/query/profile
type RespProfile struct {
	DisplayName string `json:"displayname,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// RespInvite is the content of a response to PUT /_coddy/federation/v1/invite/{frameID}/{eventID}
type RespInvite struct {
	// The invite event signed by recipient server.
	Event spec.RawJSON `json:"event"`
}

// MarshalJSON implements json.Marshaller
func (r RespInvite) MarshalJSON() ([]byte, error) {
	// The wire format of a RespInvite is slightly is sent as the second element
	// of a two element list where the first element is the constant integer 200.
	// (This protocol oddity is the result of a typo in the synapse coddy
	//  server, and is preserved to maintain compatibility.)
	return json.Marshal([]interface{}{200, respInviteFields(r)})
}

// UnmarshalJSON implements json.Unmarshaller
func (r *RespInvite) UnmarshalJSON(data []byte) error {
	var tuple xtools.EventJSONs
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) != 2 {
		return fmt.Errorf("xtools: invalid invite response, invalid length: %d != 2", len(tuple))
	}
	if jr := gjson.GetBytes(tuple[1], "event"); jr.Exists() {
		r.Event = []byte(jr.Raw)
	}
	return nil
}

type respInviteFields struct {
	Event spec.RawJSON `json:"event"`
}

// RespInvite is the content of a response to PUT /_coddy/federation/v2/invite/{frameID}/{eventID}
type RespInviteV2 struct {
	// The invite event signed by recipient server.
	Event spec.RawJSON `json:"event"`
}

// RespClaimKeys is the response for post-coddy-federation-v1-user-keys-claim
type RespClaimKeys struct {
	// Required. One-time keys for the queried devices. A map from user ID, to a map from devices to a map
	// from <algorithm>:<key_id> to the key object or a string.
	OneTimeKeys map[string]map[string]map[string]json.RawMessage `json:"one_time_keys"`
}

// RespQueryKeys is the response for post-coddy-federation-v1-user-keys-query
type RespQueryKeys struct {
	DeviceKeys      map[string]map[string]DeviceKeys `json:"device_keys"`
	MasterKeys      map[string]CrossSigningKey       `json:"master_keys"`
	SelfSigningKeys map[string]CrossSigningKey       `json:"self_signing_keys"`
}

// DeviceKeys as per post-coddy-federation-v1-user-keys-query
type DeviceKeys struct {
	RespUserDeviceKeys
	// Additional data added to the device key information by intermediate servers, and not covered by the signatures.
	// E.g { "device_display_name": "Alice's mobile phone" }
	Unsigned map[string]interface{} `json:"unsigned"`
}

func (s *DeviceKeys) isCrossSigningBody() {} // implements CrossSigningBody

func (s *DeviceKeys) Scan(src interface{}) error {
	switch v := src.(type) {
	case string:
		return json.Unmarshal([]byte(v), s)
	case []byte:
		return json.Unmarshal(v, s)
	}
	return fmt.Errorf("unsupported source type")
}

func (s DeviceKeys) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// A Version is a struct that matches the version response from a Coddy homeserver. See
type Version struct {
	// Server is a struct containing the homserver version values
	Server struct {
		// Name is an arbitrary string that the Coddy server uses to identify itself
		Name string `json:"name"`
		// Version is a string that identifies the Coddy server's version, the format
		// of which depends on the Matrx server implementation
		Version string `json:"version"`
	} `json:"server"`
}

// MSC2836EventRelationshipsRequest is a request to /event_relationships from
// nolint:maligned
type MSC2836EventRelationshipsRequest struct {
	EventID         string `json:"event_id"`
	MaxDepth        int    `json:"max_depth"`
	MaxBreadth      int    `json:"max_breadth"`
	Limit           int    `json:"limit"`
	DepthFirst      bool   `json:"depth_first"`
	RecentFirst     bool   `json:"recent_first"`
	IncludeParent   bool   `json:"include_parent"`
	IncludeChildren bool   `json:"include_children"`
	Direction       string `json:"direction"`
	Batch           string `json:"batch"`
	AutoJoin        bool   `json:"auto_join"`
}

// NewMSC2836EventRelationshipsRequest creates a new MSC2836 /event_relationships request with defaults set.
// https://github.com/coddy-org/coddy-doc/blob/kegan/msc/threading/proposals/2836-threading.md
func NewMSC2836EventRelationshipsRequest(body io.Reader) (*MSC2836EventRelationshipsRequest, error) {
	var relation MSC2836EventRelationshipsRequest
	relation.Defaults()
	if err := json.NewDecoder(body).Decode(&relation); err != nil {
		return nil, err
	}
	return &relation, nil
}

// Defaults sets default values.
func (r *MSC2836EventRelationshipsRequest) Defaults() {
	r.Limit = 100
	r.MaxBreadth = 10
	r.MaxDepth = 3
	r.DepthFirst = false
	r.RecentFirst = true
	r.IncludeParent = false
	r.IncludeChildren = false
	r.Direction = "down"
}

// MSC2836EventRelationshipsResponse is a response to /event_relationships from
// https://github.com/coddy-org/coddy-doc/blob/kegan/msc/threading/proposals/2836-threading.md
type MSC2836EventRelationshipsResponse struct {
	Events    xtools.EventJSONs `json:"events"`
	NextBatch string            `json:"next_batch"`
	Limited   bool              `json:"limited"`
	AuthChain xtools.EventJSONs `json:"auth_chain"`
}

// FrameHierarchyFrame represents a public frame with additional metadata on the space directory
type FrameHierarchyFrame struct {
	PublicFrame
	ChildrenState  []FrameHierarchyStrippedEvent `json:"children_state"`
	AllowedFrameIDs []string                     `json:"allowed_frame_ids,omitempty"`
	FrameType       string                       `json:"frame_type"`
}

// FrameHierarchyResponse is the HTTP response body for the federation /unstable/spaces/{frameID} endpoint
// See https://github.com/coddy-org/coddy-doc/pull/2946
type FrameHierarchyResponse struct {
	Frame                 FrameHierarchyFrame   `json:"frame"`
	Children             []FrameHierarchyFrame `json:"children"`
	InaccessibleChildren []string            `json:"inaccessible_children"`
}

// FrameHierarchyStrippedEvent is the format of events returned in the HTTP response body
type FrameHierarchyStrippedEvent struct {
	Type           string          `json:"type"`
	StateKey       string          `json:"state_key"`
	Content        json.RawMessage `json:"content"`
	Sender         string          `json:"sender"`
	OriginServerTS spec.Timestamp  `json:"origin_server_ts"`
}
