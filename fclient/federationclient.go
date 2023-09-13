package fclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/withqb/xcore"
	"github.com/withqb/xtools"
	"github.com/withqb/xtools/spec"
	"golang.org/x/crypto/ed25519"
)

// an interface for gmsl.FederationClient - contains functions called by federationapi only.
type FederationClient interface {
	xtools.KeyClient

	DoRequestAndParseResponse(ctx context.Context, req *http.Request, result interface{}) error

	SendTransaction(ctx context.Context, t xtools.Transaction) (res RespSend, err error)

	// Perform operations
	LookupFrameAlias(ctx context.Context, origin, s spec.ServerName, frameAlias string) (res RespDirectory, err error)
	Peek(ctx context.Context, origin, s spec.ServerName, frameID, peekID string, frameVersions []xtools.FrameVersion) (res RespPeek, err error)
	MakeJoin(ctx context.Context, origin, s spec.ServerName, frameID, userID string) (res RespMakeJoin, err error)
	SendJoin(ctx context.Context, origin, s spec.ServerName, event xtools.PDU) (res RespSendJoin, err error)
	MakeLeave(ctx context.Context, origin, s spec.ServerName, frameID, userID string) (res RespMakeLeave, err error)
	SendLeave(ctx context.Context, origin, s spec.ServerName, event xtools.PDU) (err error)
	SendInviteV2(ctx context.Context, origin, s spec.ServerName, request InviteV2Request) (res RespInviteV2, err error)
	SendInviteV3(ctx context.Context, origin, s spec.ServerName, request InviteV3Request, userID spec.UserID) (res RespInviteV2, err error)

	GetEvent(ctx context.Context, origin, s spec.ServerName, eventID string) (res xtools.Transaction, err error)

	GetEventAuth(ctx context.Context, origin, s spec.ServerName, frameVersion xtools.FrameVersion, frameID, eventID string) (res RespEventAuth, err error)
	GetUserDevices(ctx context.Context, origin, s spec.ServerName, userID string) (RespUserDevices, error)
	ClaimKeys(ctx context.Context, origin, s spec.ServerName, oneTimeKeys map[string]map[string]string) (RespClaimKeys, error)
	QueryKeys(ctx context.Context, origin, s spec.ServerName, keys map[string][]string) (RespQueryKeys, error)
	Backfill(ctx context.Context, origin, s spec.ServerName, frameID string, limit int, eventIDs []string) (res xtools.Transaction, err error)
	MSC2836EventRelationships(ctx context.Context, origin, dst spec.ServerName, r MSC2836EventRelationshipsRequest, frameVersion xtools.FrameVersion) (res MSC2836EventRelationshipsResponse, err error)
	FrameHierarchy(ctx context.Context, origin, dst spec.ServerName, frameID string, suggestedOnly bool) (res FrameHierarchyResponse, err error)

	ExchangeThirdPartyInvite(ctx context.Context, origin, s spec.ServerName, builder xtools.ProtoEvent) (err error)
	LookupState(ctx context.Context, origin, s spec.ServerName, frameID string, eventID string, frameVersion xtools.FrameVersion) (res RespState, err error)
	LookupStateIDs(ctx context.Context, origin, s spec.ServerName, frameID string, eventID string) (res RespStateIDs, err error)
	LookupMissingEvents(ctx context.Context, origin, s spec.ServerName, frameID string, missing MissingEvents, frameVersion xtools.FrameVersion) (res RespMissingEvents, err error)

	GetPublicFrames(
		ctx context.Context, origin, s spec.ServerName, limit int, since string,
		includeAllNetworks bool, thirdPartyInstanceID string,
	) (res RespPublicFrames, err error)
	GetPublicFramesFiltered(
		ctx context.Context, origin, s spec.ServerName, limit int, since, filter string,
		includeAllNetworks bool, thirdPartyInstanceID string,
	) (res RespPublicFrames, err error)

	LookupProfile(
		ctx context.Context, origin, s spec.ServerName, userID string, field string,
	) (res RespProfile, err error)

	P2PSendTransactionToRelay(ctx context.Context, u spec.UserID, t xtools.Transaction, forwardingServer spec.ServerName) (res EmptyResp, err error)
	P2PGetTransactionFromRelay(ctx context.Context, u spec.UserID, prev RelayEntry, relayServer spec.ServerName) (res RespGetRelayTransaction, err error)
}

// A FederationClient is a coddy federation client that adds
// "Authorization: X-Matrix" headers to requests that need ed25519 signatures
type federationClient struct {
	Client
	identities []*SigningIdentity
}

type SigningIdentity struct {
	// YAML annotations so it can be used directly in Dendrite config.
	ServerName spec.ServerName    `yaml:"server_name"`
	KeyID      xtools.KeyID       `yaml:"key_id"`
	PrivateKey ed25519.PrivateKey `yaml:"-"`
}

// NewFederationClient makes a new FederationClient. You can supply
// zero or more ClientOptions which control the transport, timeout,
// TLS validation etc - see WithTransport, WithTimeout, WithSkipVerify,
// WithDNSCache etc.
func NewFederationClient(
	identities []*SigningIdentity,
	options ...ClientOption,
) FederationClient {
	return &federationClient{
		Client: *NewClient(
			append(options, WithWellKnownSRVLookups(true))...,
		),
		identities: append([]*SigningIdentity{}, identities...),
	}
}

func (ac *federationClient) DoRequestAndParseResponse(ctx context.Context, req *http.Request, result interface{}) error {
	return ac.Client.DoRequestAndParseResponse(ctx, req, result)
}

func (ac *federationClient) doRequest(ctx context.Context, r FederationRequest, resBody interface{}) error {
	var identity *SigningIdentity
	for _, id := range ac.identities {
		if id.ServerName == r.Origin() {
			identity = id
			break
		}
	}
	if identity == nil {
		return fmt.Errorf("no signing identity for server name %q", r.Origin())
	}
	if err := r.Sign(identity.ServerName, identity.KeyID, identity.PrivateKey); err != nil {
		return err
	}

	req, err := r.HTTPRequest()
	if err != nil {
		return err
	}

	return ac.Client.DoRequestAndParseResponse(ctx, req, resBody)
}

var federationPathPrefixV1 = "/_coddy/federation/v1"
var federationPathPrefixV2 = "/_coddy/federation/v2"
var federationPathPrefixV3 = "/_coddy/federation/v3"

// SendTransaction sends a transaction
func (ac *federationClient) SendTransaction(
	ctx context.Context, t xtools.Transaction,
) (res RespSend, err error) {
	path := federationPathPrefixV1 + "/send/" + string(t.TransactionID)
	req := NewFederationRequest("PUT", t.Origin, t.Destination, path)
	if err = req.SetContent(t); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// P2PSendTransactionToRelay sends a transaction for forwarding to the destination.
func (ac *federationClient) P2PSendTransactionToRelay(
	ctx context.Context, u spec.UserID, t xtools.Transaction, forwardingServer spec.ServerName,
) (res EmptyResp, err error) {
	path := federationPathPrefixV1 + "/send_relay/" +
		string(t.TransactionID) + "/" +
		url.PathEscape(u.String())
	req := NewFederationRequest("PUT", t.Origin, forwardingServer, path)
	if err = req.SetContent(t); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// P2PGetTransactionFromRelay requests a transaction from a relay destined for this server.
func (ac *federationClient) P2PGetTransactionFromRelay(
	ctx context.Context, u spec.UserID, prev RelayEntry, relayServer spec.ServerName,
) (res RespGetRelayTransaction, err error) {
	path := federationPathPrefixV1 + "/relay_txn/" + url.PathEscape(u.String())
	req := NewFederationRequest("GET", u.Domain(), relayServer, path)
	if err = req.SetContent(prev); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// Creates a version query string with all the specified frame versions, typically
// the list of all supported frame versions.
// Needed when making a /make_knock or /make_join request.
func makeVersionQueryString(frameVersions []xtools.FrameVersion) string {
	versionQueryString := ""
	if len(frameVersions) > 0 {
		vqs := make([]string, 0, len(frameVersions))
		for _, v := range frameVersions {
			vqs = append(vqs, fmt.Sprintf("ver=%s", url.QueryEscape(string(v))))
		}
		versionQueryString = "?" + strings.Join(vqs, "&")
	}
	return versionQueryString
}

// Takes the map of frame version implementations and converts it into a list of
// frame version strings.
func frameVersionsToList(
	versionsMap map[xtools.FrameVersion]xtools.IFrameVersion,
) []xtools.FrameVersion {
	var supportedVersions []xtools.FrameVersion
	for version := range versionsMap {
		supportedVersions = append(supportedVersions, version)
	}
	return supportedVersions
}

// MakeJoin makes a join m.frame.member event for a frame on a remote coddy server.
// This is used to join a frame the local server isn't a member of.
// We need to query a remote server because if we aren't in the frame we don't
// know what to use for the "prev_events" in the join event.
// The remote server should return us a m.frame.member event for our local user
// with the "prev_events" filled out.
// If this successfully returns an acceptable event we will sign it with our
// server's key and pass it to SendJoin.
func (ac *federationClient) MakeJoin(
	ctx context.Context, origin, s spec.ServerName, frameID, userID string,
) (res RespMakeJoin, err error) {
	frameVersions := frameVersionsToList(xtools.FrameVersions())
	versionQueryString := makeVersionQueryString(frameVersions)
	path := federationPathPrefixV1 + "/make_join/" +
		url.PathEscape(frameID) + "/" +
		url.PathEscape(userID) + versionQueryString
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendJoin sends a join m.frame.member event obtained using MakeJoin via a
// remote coddy server.
// This is used to join a frame the local server isn't a member of.
func (ac *federationClient) SendJoin(
	ctx context.Context, origin, s spec.ServerName, event xtools.PDU,
) (res RespSendJoin, err error) {
	return ac.sendJoin(ctx, origin, s, event, false)
}

// SendJoinPartialState sends a join m.frame.member event obtained using MakeJoin via a
// remote coddy server, with a parameter indicating we support partial state in
// the response.
// This is used to join a frame the local server isn't a member of.
func (ac *federationClient) SendJoinPartialState(
	ctx context.Context, origin, s spec.ServerName, event xtools.PDU,
) (res RespSendJoin, err error) {
	return ac.sendJoin(ctx, origin, s, event, true)
}

// sendJoin is an internal implementation shared between SendJoin and SendJoinPartialState
func (ac *federationClient) sendJoin(
	ctx context.Context, origin, s spec.ServerName, event xtools.PDU, partialState bool,
) (res RespSendJoin, err error) {
	path := federationPathPrefixV2 + "/send_join/" +
		url.PathEscape(event.FrameID()) + "/" +
		url.PathEscape(event.EventID())
	if partialState {
		path += "?omit_members=true"
	}

	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	gerr, ok := err.(xcore.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		v1path := federationPathPrefixV1 + "/send_join/" +
			url.PathEscape(event.FrameID()) + "/" +
			url.PathEscape(event.EventID())
		v1req := NewFederationRequest("PUT", origin, s, v1path)
		if err = v1req.SetContent(event); err != nil {
			return
		}
		var v1Res []json.RawMessage
		err = ac.doRequest(ctx, v1req, &v1Res)
		if err == nil && len(v1Res) == 2 {
			err = json.Unmarshal(v1Res[1], &res)
		}
	}
	return
}

// MakeKnock makes a join m.frame.member event for a frame on a remote coddy server.
// This is used to knock upon a frame the local server isn't a member of.
// We need to query a remote server because if we aren't in the frame we don't
// know what to use for the `prev_events` and `auth_events` in the knock event.
// The remote server should return us a populated m.frame.member event for our local user.
// If this successfully returns an acceptable event we will sign it with our
// server's key and pass it to SendKnock.
func (ac *federationClient) MakeKnock(
	ctx context.Context, origin, s spec.ServerName, frameID, userID string,
	frameVersions []xtools.FrameVersion,
) (res RespMakeKnock, err error) {
	versionQueryString := makeVersionQueryString(frameVersions)
	path := federationPathPrefixV1 + "/make_knock/" +
		url.PathEscape(frameID) + "/" +
		url.PathEscape(userID) + versionQueryString
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendKnock sends a join m.frame.member event obtained using MakeKnock via a
// remote coddy server.
// This is used to ask to join a frame the local server isn't a member of.
func (ac *federationClient) SendKnock(
	ctx context.Context, origin, s spec.ServerName, event xtools.PDU,
) (res RespSendKnock, err error) {
	path := federationPathPrefixV1 + "/send_knock/" +
		url.PathEscape(event.FrameID()) + "/" +
		url.PathEscape(event.EventID())

	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// MakeLeave makes a leave m.frame.member event for a frame on a remote coddy server.
// This is used to reject a remote invite and is similar to MakeJoin.
// If this successfully returns an acceptable event we will sign it, replace
// the event_id with our own, and pass it to SendLeave.
func (ac *federationClient) MakeLeave(
	ctx context.Context, origin, s spec.ServerName, frameID, userID string,
) (res RespMakeLeave, err error) {
	path := federationPathPrefixV1 + "/make_leave/" +
		url.PathEscape(frameID) + "/" +
		url.PathEscape(userID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendLeave sends a leave m.frame.member event obtained using MakeLeave via a
// remote coddy server.
// This is used to reject a remote invite.
func (ac *federationClient) SendLeave(
	ctx context.Context, origin, s spec.ServerName, event xtools.PDU,
) (err error) {
	path := federationPathPrefixV2 + "/send_leave/" +
		url.PathEscape(event.FrameID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	res := struct{}{}
	err = ac.doRequest(ctx, req, &res)
	gerr, ok := err.(xcore.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		v1path := federationPathPrefixV1 + "/send_leave/" +
			url.PathEscape(event.FrameID()) + "/" +
			url.PathEscape(event.EventID())
		v1req := NewFederationRequest("PUT", origin, s, v1path)
		if err = v1req.SetContent(event); err != nil {
			return
		}
		var v1Res []json.RawMessage
		err = ac.doRequest(ctx, v1req, &v1Res)
		if err == nil && len(v1Res) == 2 {
			err = json.Unmarshal(v1Res[1], &res)
		}
	}
	return
}

// SendInvite sends an invite m.frame.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
func (ac *federationClient) SendInvite(
	ctx context.Context, origin, s spec.ServerName, event xtools.PDU,
) (res RespInvite, err error) {
	path := federationPathPrefixV1 + "/invite/" +
		url.PathEscape(event.FrameID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(event); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// SendInviteV2 sends an invite m.frame.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
func (ac *federationClient) SendInviteV2(
	ctx context.Context, origin, s spec.ServerName, request InviteV2Request,
) (res RespInviteV2, err error) {
	event := request.Event()
	path := federationPathPrefixV2 + "/invite/" +
		url.PathEscape(event.FrameID()) + "/" +
		url.PathEscape(event.EventID())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(request); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)

	gerr, ok := err.(xcore.HTTPError)
	if ok && gerr.Code == 404 {
		// fallback to v1 which returns [200, body]
		var resp RespInvite
		resp, err = ac.SendInvite(ctx, origin, s, request.Event())
		if err != nil {
			return
		}
		// assume v1 as per spec: put-coddy-federation-v1-invite-frameid-eventid
		// Servers which receive a v1 invite request must assume that the frame version is either "1" or "2".
		res = RespInviteV2{ // nolint:gosimple
			Event: resp.Event,
		}
	}
	return
}

// SendInviteV3 sends an invite m.frame.member event to an invited server to be
// signed by it. This is used to invite a user that is not on the local server.
// V3 sends a partial event to allow the invitee to populate the mxid_mapping.
func (ac *federationClient) SendInviteV3(
	ctx context.Context, origin, s spec.ServerName, request InviteV3Request, userID spec.UserID,
) (res RespInviteV2, err error) {
	path := federationPathPrefixV3 + "/invite/" +
		url.PathEscape(request.Event().FrameID) + "/" +
		url.PathEscape(userID.String())
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(request); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// ExchangeThirdPartyInvite sends the builder of a m.frame.member event of
// "invite" membership derived from a response from invites sent by an identity
// server.
// This is used to exchange a m.frame.third_party_invite event for a m.frame.member
// one in a frame the local server isn't a member of.
func (ac *federationClient) ExchangeThirdPartyInvite(
	ctx context.Context, origin, s spec.ServerName, proto xtools.ProtoEvent,
) (err error) {
	path := federationPathPrefixV1 + "/exchange_third_party_invite/" +
		url.PathEscape(proto.FrameID)
	req := NewFederationRequest("PUT", origin, s, path)
	if err = req.SetContent(proto); err != nil {
		return
	}
	res := struct{}{}
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupState retrieves the frame state for a frame at an event from a
// remote coddy server as full coddy events.
func (ac *federationClient) LookupState(
	ctx context.Context, origin, s spec.ServerName, frameID, eventID string, frameVersion xtools.FrameVersion,
) (res RespState, err error) {
	path := federationPathPrefixV1 + "/state/" +
		url.PathEscape(frameID) +
		"?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupStateIDs retrieves the frame state for a frame at an event from a
// remote coddy server as lists of coddy event IDs.
func (ac *federationClient) LookupStateIDs(
	ctx context.Context, origin, s spec.ServerName, frameID, eventID string,
) (res RespStateIDs, err error) {
	path := federationPathPrefixV1 + "/state_ids/" +
		url.PathEscape(frameID) +
		"?event_id=" +
		url.QueryEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupMissingEvents asks a remote server for missing events within a
// given bracket.
func (ac *federationClient) LookupMissingEvents(
	ctx context.Context, origin, s spec.ServerName, frameID string,
	missing MissingEvents, frameVersion xtools.FrameVersion,
) (res RespMissingEvents, err error) {
	path := federationPathPrefixV1 + "/get_missing_events/" +
		url.PathEscape(frameID)
	req := NewFederationRequest("POST", origin, s, path)
	if err = req.SetContent(missing); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// Peek starts a peek on a remote server: see MSC2753
func (ac *federationClient) Peek(
	ctx context.Context, origin, s spec.ServerName, frameID, peekID string,
	frameVersions []xtools.FrameVersion,
) (res RespPeek, err error) {
	versionQueryString := ""
	if len(frameVersions) > 0 {
		var vqs []string
		for _, v := range frameVersions {
			vqs = append(vqs, fmt.Sprintf("ver=%s", url.QueryEscape(string(v))))
		}
		versionQueryString = "?" + strings.Join(vqs, "&")
	}
	path := federationPathPrefixV1 + "/peek/" +
		url.PathEscape(frameID) + "/" +
		url.PathEscape(peekID) + versionQueryString
	req := NewFederationRequest("PUT", origin, s, path)
	var empty struct{}
	if err = req.SetContent(empty); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupFrameAlias looks up a frame alias hosted on the remote server.
// The domain part of the frameAlias must match the name of the server it is
// being looked up on.
// If the frame alias doesn't exist on the remote server then a 404 xcore.HTTPError
// is returned.
func (ac *federationClient) LookupFrameAlias(
	ctx context.Context, origin, s spec.ServerName, frameAlias string,
) (res RespDirectory, err error) {
	path := federationPathPrefixV1 + "/query/directory?frame_alias=" +
		url.QueryEscape(frameAlias)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetPublicFrames gets all public frames listed on the target homeserver's directory.
// thirdPartyInstanceID can only be non-empty if includeAllNetworks is false.
func (ac *federationClient) GetPublicFrames(
	ctx context.Context, origin, s spec.ServerName, limit int, since string,
	includeAllNetworks bool, thirdPartyInstanceID string,
) (res RespPublicFrames, err error) {
	return ac.GetPublicFramesFiltered(ctx, origin, s, limit, since, "", includeAllNetworks, thirdPartyInstanceID)
}

// searchTerm is used when querying e.g. remote public frames
type searchTerm struct {
	GenericSearchTerm string `json:"generic_search_term,omitempty"`
}

// postPublicFramesReq is a request to /publicFrames
type postPublicFramesReq struct {
	PublicFramesFilter    searchTerm `json:"filter,omitempty"`
	Limit                int        `json:"limit,omitempty"`
	IncludeAllNetworks   bool       `json:"include_all_networks,omitempty"`
	ThirdPartyInstanceID string     `json:"third_party_instance_id,omitempty"`
	Since                string     `json:"since,omitempty"`
}

// GetPublicFramesFiltered gets a filtered public frames list from the target homeserver's directory.
// thirdPartyInstanceID can only be non-empty if includeAllNetworks is false.
func (ac *federationClient) GetPublicFramesFiltered(
	ctx context.Context, origin, s spec.ServerName, limit int, since, filter string,
	includeAllNetworks bool, thirdPartyInstanceID string,
) (res RespPublicFrames, err error) {
	if includeAllNetworks && thirdPartyInstanceID != "" {
		return res, fmt.Errorf("thirdPartyInstanceID can only be used if includeAllNetworks is false")
	}

	framesReq := postPublicFramesReq{
		PublicFramesFilter:    searchTerm{GenericSearchTerm: filter},
		Limit:                limit,
		IncludeAllNetworks:   includeAllNetworks,
		ThirdPartyInstanceID: thirdPartyInstanceID,
		Since:                since,
	}
	path := federationPathPrefixV1 + "/publicFrames"
	req := NewFederationRequest("POST", origin, s, path)
	if err = req.SetContent(framesReq); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// LookupProfile queries the profile of a user.
// If field is empty, the server returns the full profile of the user.
// Otherwise, it must be one of: ["displayname", "avatar_url"], indicating
// which field of the profile should be returned.
func (ac *federationClient) LookupProfile(
	ctx context.Context, origin, s spec.ServerName, userID string, field string,
) (res RespProfile, err error) {
	path := federationPathPrefixV1 + "/query/profile?user_id=" +
		url.QueryEscape(userID)
	if field != "" {
		path += "&field=" + url.QueryEscape(field)
	}
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// ClaimKeys claims E2E one-time keys from a remote server.
// `oneTimeKeys` are the keys to be claimed. A map from user ID, to a map from device ID to algorithm name. E.g:
//
//	{
//	  "@alice:example.com": {
//	    "JLAFKJWSCS": "signed_curve25519"
//	  }
//	}
//
// post-coddy-federation-v1-user-keys-claim
func (ac *federationClient) ClaimKeys(ctx context.Context, origin, s spec.ServerName, oneTimeKeys map[string]map[string]string) (res RespClaimKeys, err error) {
	path := federationPathPrefixV1 + "/user/keys/claim"
	req := NewFederationRequest("POST", origin, s, path)
	if err = req.SetContent(map[string]interface{}{
		"one_time_keys": oneTimeKeys,
	}); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// QueryKeys queries E2E device keys from a remote server.
// post-coddy-federation-v1-user-keys-query
func (ac *federationClient) QueryKeys(ctx context.Context, origin, s spec.ServerName, keys map[string][]string) (res RespQueryKeys, err error) {
	path := federationPathPrefixV1 + "/user/keys/query"
	req := NewFederationRequest("POST", origin, s, path)
	if err = req.SetContent(map[string]interface{}{
		"device_keys": keys,
	}); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetEvent gets an event by ID from a remote server.
func (ac *federationClient) GetEvent(
	ctx context.Context, origin, s spec.ServerName, eventID string,
) (res xtools.Transaction, err error) {
	path := federationPathPrefixV1 + "/event/" + url.PathEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetEventAuth gets an event auth chain from a remote server.
// See get-coddy-federation-v1-event-auth-frameid-eventid
func (ac *federationClient) GetEventAuth(
	ctx context.Context, origin, s spec.ServerName, frameVersion xtools.FrameVersion, frameID, eventID string,
) (res RespEventAuth, err error) {
	path := federationPathPrefixV1 + "/event_auth/" + url.PathEscape(frameID) + "/" + url.PathEscape(eventID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// GetUserDevices returns a list of the user's devices from a remote server.
// See get-coddy-federation-v1-user-devices-userid
func (ac *federationClient) GetUserDevices(
	ctx context.Context, origin, s spec.ServerName, userID string,
) (res RespUserDevices, err error) {
	path := federationPathPrefixV1 + "/user/devices/" + url.PathEscape(userID)
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// Backfill asks a homeserver for events early enough for them to not be in the
// local database.
func (ac *federationClient) Backfill(
	ctx context.Context, origin, s spec.ServerName, frameID string, limit int, eventIDs []string,
) (res xtools.Transaction, err error) {
	// Parse the limit into a string so that we can include it in the URL's query.
	limitStr := strconv.Itoa(limit)

	// Define the URL's query.
	query := url.Values{}
	query["v"] = eventIDs
	query.Set("limit", limitStr)

	// Use the url.URL structure to easily generate the request's URI (path?query).
	u := url.URL{
		Path:     "/_coddy/federation/v1/backfill/" + frameID,
		RawQuery: query.Encode(),
	}
	path := u.RequestURI()

	// Send the request.
	req := NewFederationRequest("GET", origin, s, path)
	err = ac.doRequest(ctx, req, &res)
	return
}

// MSC2836EventRelationships performs an MSC2836 /event_relationships request.
func (ac *federationClient) MSC2836EventRelationships(
	ctx context.Context, origin, dst spec.ServerName, r MSC2836EventRelationshipsRequest, frameVersion xtools.FrameVersion,
) (res MSC2836EventRelationshipsResponse, err error) {
	path := "/_coddy/federation/unstable/event_relationships"
	req := NewFederationRequest("POST", origin, dst, path)
	if err = req.SetContent(r); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}

func (ac *federationClient) FrameHierarchy(
	ctx context.Context, origin, dst spec.ServerName, frameID string, suggestedOnly bool,
) (res FrameHierarchyResponse, err error) {
	path := "/_coddy/federation/v1/hierarchy/" + url.PathEscape(frameID)
	if suggestedOnly {
		path += "?suggested_only=true"
	}
	req := NewFederationRequest("GET", origin, dst, path)
	err = ac.doRequest(ctx, req, &res)
	if err != nil {
		gerr, ok := err.(xcore.HTTPError)
		if ok && gerr.Code == 404 {
			// fallback to unstable endpoint
			path = "/_coddy/federation/unstable/org.coddy.msc2946/hierarchy/" + url.PathEscape(frameID)
			if suggestedOnly {
				path += "?suggested_only=true"
			}
			req := NewFederationRequest("GET", origin, dst, path)
			err = ac.doRequest(ctx, req, &res)
		}
	}
	return
}
