package iscpworkbench

import (
	"encoding/json"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

// The pinned SDK records the outer receive sequence before AEAD.Open. Verify
// the same authenticated bytes first so forged input cannot consume a sequence.
// The SDK still performs all identity/replay checks; Core wire is unchanged.
func authenticateEnvelope(provider iscpcrypto.Provider, s *session.State, env envelope.SecureEnvelope) error {
	nonce, err := iscpcrypto.DecodeBase64URL(env.Nonce)
	if err != nil {
		return err
	}
	ciphertext, err := iscpcrypto.DecodeBase64URL(env.Ciphertext)
	if err != nil {
		return err
	}
	copy := env
	copy.Ciphertext = ""
	raw, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	aad, err := canonical.Marshal(raw)
	if err != nil {
		return err
	}
	_, err = provider.Open(s.ReceiveKey, nonce, ciphertext, aad)
	return err
}
