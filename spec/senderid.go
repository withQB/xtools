package spec

import (
	"context"

	"golang.org/x/crypto/ed25519"
)

type SenderID string

type UserIDForSender func(frameID FrameID, senderID SenderID) (*UserID, error)
type SenderIDForUser func(frameID FrameID, userID UserID) (*SenderID, error)

// CreateSenderID is a function used to create the pseudoID private key.
type CreateSenderID func(ctx context.Context, userID UserID, frameID FrameID, frameVersion string) (SenderID, ed25519.PrivateKey, error)

// StoreSenderIDFromPublicID is a function to store the mxid_mapping after receiving a join event over federation.
type StoreSenderIDFromPublicID func(ctx context.Context, senderID SenderID, userID string, id FrameID) error

// Create a new sender ID from a private frame key
func SenderIDFromPseudoIDKey(key ed25519.PrivateKey) SenderID {
	return SenderID(Base64Bytes(key.Public().(ed25519.PublicKey)).Encode())
}

// Create a new sender ID from a user ID
func SenderIDFromUserID(user UserID) SenderID {
	return SenderID(user.String())
}

// Decodes this sender ID as base64, i.e. returns the raw bytes of the
// pseudo ID used to create this SenderID, assuming this SenderID was made
// using a pseudo ID.
func (s SenderID) RawBytes() (res Base64Bytes, err error) {
	err = res.Decode(string(s))
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Returns true if this SenderID was made using a user ID
func (s SenderID) IsUserID() bool {
	// Key is base64, @ is not a valid base64 char
	// So if string starts with @, then this sender ID must
	// be a user ID
	return string(s)[0] == '@'
}

// Returns true if this SenderID was made using a pseudo ID
func (s SenderID) IsPseudoID() bool {
	return !s.IsUserID()
}

// Returns the non-nil UserID used to create this SenderID, or nil
// if this SenderID was not created using a UserID
func (s SenderID) ToUserID() *UserID {
	if s.IsUserID() {
		uID, _ := NewUserID(string(s), true)
		return uID
	}

	return nil
}

// Returns the non-nil frame public key (pseudo ID) used to create this
// SenderID, or nil if this SenderID was not created using a pseudo ID
func (s SenderID) ToPseudoID() *ed25519.PublicKey {
	if s.IsPseudoID() {
		decoded, err := s.RawBytes()
		if err != nil {
			return nil
		}
		key := ed25519.PublicKey([]byte(decoded))
		return &key
	}

	return nil
}
