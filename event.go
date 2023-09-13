package xtools

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/withqb/xtools/spec"
)

// Event validation errors
const (
	EventValidationTooLarge int = 1
)

// EventValidationError is returned if there is a problem validating an event
type EventValidationError struct {
	Message     string
	Code        int
	Persistable bool
}

func (e EventValidationError) Error() string {
	return e.Message
}

type eventFields struct {
	FrameID         string         `json:"frame_id"`
	SenderID       string         `json:"sender"`
	Type           string         `json:"type"`
	StateKey       *string        `json:"state_key"`
	Content        spec.RawJSON   `json:"content"`
	Redacts        string         `json:"redacts"`
	Depth          int64          `json:"depth"`
	Unsigned       spec.RawJSON   `json:"unsigned,omitempty"`
	OriginServerTS spec.Timestamp `json:"origin_server_ts"`
	//Origin         spec.ServerName `json:"origin"`
}

var emptyEventReferenceList = []eventReference{}

const (
	// The event ID, frame ID, sender, event type and state key fields cannot be
	// bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L173-L182
	maxIDLength = 255
	// The entire event JSON, including signatures cannot be bigger than this.
	// https://github.com/matrix-org/synapse/blob/v0.21.0/synapse/event_auth.py#L183-184
	maxEventLength = 65536
)

func checkID(id, kind string, sigil byte) (err error) {
	if _, err = domainFromID(id); err != nil {
		return
	}
	if id[0] != sigil {
		err = fmt.Errorf(
			"gomatrixserverlib: invalid %s ID, wanted first byte to be '%c' got '%c'",
			kind, sigil, id[0],
		)
		return
	}
	if l := utf8.RuneCountInString(id); l > maxIDLength {
		err = EventValidationError{
			Code:    EventValidationTooLarge,
			Message: fmt.Sprintf("gomatrixserverlib: %s ID is too long, length %d > maximum %d", kind, l, maxIDLength),
		}
		return
	}
	if l := len(id); l > maxIDLength {
		err = EventValidationError{
			Code:        EventValidationTooLarge,
			Message:     fmt.Sprintf("gomatrixserverlib: %s ID is too long, length %d bytes > maximum %d bytes", kind, l, maxIDLength),
			Persistable: true,
		}
		return
	}
	return
}

// SplitID splits a matrix ID into a local part and a server name.
func SplitID(sigil byte, id string) (local string, domain spec.ServerName, err error) {
	// IDs have the format: SIGIL LOCALPART ":" DOMAIN
	// Split on the first ":" character since the domain can contain ":"
	// characters.
	if len(id) == 0 || id[0] != sigil {
		return "", "", fmt.Errorf("gomatrixserverlib: invalid ID %q doesn't start with %q", id, sigil)
	}
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		// The ID must have a ":" character.
		return "", "", fmt.Errorf("gomatrixserverlib: invalid ID %q missing ':'", id)
	}
	return parts[0][1:], spec.ServerName(parts[1]), nil
}
