package iscpnodeissuer

import (
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

const ControlAuthorityPath = control.AuthorityPath

type ControlAuthorityRequest = control.AuthorityRequest
type ControlAuthorityResponse = control.AuthorityResponse

func NewControlAuthorityRequest(actor identity.Device, subject control.Subject, target control.Target) (ControlAuthorityRequest, error) {
	return control.NewAuthorityRequest(actor, subject, target)
}
func NewControlAuthorityResponse(q ControlAuthorityRequest, a ControlAuthority, signer identity.Device) (ControlAuthorityResponse, error) {
	return control.NewAuthorityResponse(q, a, signer)
}
