package spec

import (
	"fmt"
	"strings"
)

const frameSigil = '!'

// A FrameID identifies a coddy frame as per the coddy specification
type FrameID struct {
	raw      string
	opaqueID string
	domain   string
}

func NewFrameID(id string) (*FrameID, error) {
	return parseAndValidateFrameID(id)
}

// Returns the full frameID string including leading sigil
func (frame *FrameID) String() string {
	return frame.raw
}

// Returns just the localpart of the frameID
func (frame *FrameID) OpaqueID() string {
	return frame.opaqueID
}

// Returns just the domain of the frameID
func (frame *FrameID) Domain() ServerName {
	return ServerName(frame.domain)
}

func parseAndValidateFrameID(id string) (*FrameID, error) {
	// NOTE: There is no length limit for frame ids
	idLength := len(id)
	if idLength < 4 { // 4 since minimum frameID includes an !, :, non-empty opaque ID, non-empty domain
		return nil, fmt.Errorf("length %d is too short to be valid", idLength)
	}

	if id[0] != frameSigil {
		return nil, fmt.Errorf("first character is not '%c'", frameSigil)
	}

	opaqueID, domain, found := strings.Cut(id[1:], string(localDomainSeparator))
	if !found {
		return nil, fmt.Errorf("at least one '%c' is expected in the frame id", localDomainSeparator)
	}
	if _, _, ok := ParseAndValidateServerName(ServerName(domain)); !ok {
		return nil, fmt.Errorf("domain is invalid")
	}

	// NOTE: There are no character limitations on the opaque part of frame ids
	opaqueLength := len(opaqueID)
	if opaqueLength < 1 {
		return nil, fmt.Errorf("opaque id length %d is too short to be valid", opaqueLength)
	}

	frameID := &FrameID{
		raw:      id,
		opaqueID: opaqueID,
		domain:   domain,
	}
	return frameID, nil
}
