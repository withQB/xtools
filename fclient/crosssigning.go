package fclient

import (
	"encoding/json"

	"github.com/tidwall/gjson"
	"github.com/withqb/xtools"
	"github.com/withqb/xtools/spec"
)

type CrossSigningKeyPurpose string

const (
	CrossSigningKeyPurposeMaster      CrossSigningKeyPurpose = "master"
	CrossSigningKeyPurposeSelfSigning CrossSigningKeyPurpose = "self_signing"
	CrossSigningKeyPurposeUserSigning CrossSigningKeyPurpose = "user_signing"
)

type CrossSigningKeys struct {
	MasterKey      CrossSigningKey `json:"master_key"`
	SelfSigningKey CrossSigningKey `json:"self_signing_key"`
	UserSigningKey CrossSigningKey `json:"user_signing_key"`
}

type CrossSigningKey struct {
	Signatures map[string]map[xtools.KeyID]spec.Base64Bytes `json:"signatures,omitempty"`
	Keys       map[xtools.KeyID]spec.Base64Bytes            `json:"keys"`
	Usage      []CrossSigningKeyPurpose                     `json:"usage"`
	UserID     string                                       `json:"user_id"`
}

func (s *CrossSigningKey) isCrossSigningBody() {} // implements CrossSigningBody

type CrossSigningBody interface {
	isCrossSigningBody()
}

type CrossSigningForKeyOrDevice struct {
	CrossSigningBody
}

// Implements json.Marshaler
func (c CrossSigningForKeyOrDevice) MarshalJSON() ([]byte, error) {
	// Marshal the contents at the top level, rather than having it embedded
	// in a "CrossSigningBody" JSON key.
	return json.Marshal(c.CrossSigningBody)
}

// Implements json.Unmarshaler
func (c *CrossSigningForKeyOrDevice) UnmarshalJSON(b []byte) error {
	if gjson.GetBytes(b, "device_id").Exists() {
		body := &DeviceKeys{}
		if err := json.Unmarshal(b, body); err != nil {
			return err
		}
		c.CrossSigningBody = body
		return nil
	}
	body := &CrossSigningKey{}
	if err := json.Unmarshal(b, body); err != nil {
		return err
	}
	c.CrossSigningBody = body
	return nil
}
