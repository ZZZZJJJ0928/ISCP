package iscpworkbench

import (
	"errors"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func validateNodeAuthorities(cfg Config, m material) error {
	if m.enrollment.Mode != iscpbridge.BundleModeWorkbenchNodeManaged || m.enrollment.RelaySignerIdentity == nil || m.enrollment.InvitationSignerIdentity == nil {
		return errors.New("node-managed profile requires explicit self-hosted trust roles")
	}
	var invitation = *m.enrollment.InvitationSignerIdentity
	if err := readJSONFile(cfg.InvitationIdentityFile, &invitation, false); err != nil {
		return errors.New("load pinned invitation authority")
	}
	if invitation.DeviceID != m.enrollment.InvitationSignerIdentity.DeviceID || invitation.DomainID != m.enrollment.DomainID || invitation.PublicKey.Public != m.enrollment.InvitationSignerIdentity.PublicKey.Public || invitation.PublicKey.KID != m.enrollment.InvitationSignerIdentity.PublicKey.KID {
		return errors.New("invitation authority does not match enrollment")
	}
	for _, id := range []identity.DeviceIdentity{invitation, m.issuer, *m.enrollment.RelaySignerIdentity} {
		if id.DomainID != m.enrollment.DomainID || iscpbridge.ValidateLocalRelaySigner(id) != nil {
			return errors.New("node-managed authority key is invalid")
		}
	}
	if invitation.PublicKey.Public == m.issuer.PublicKey.Public || invitation.PublicKey.Public == m.enrollment.RelaySignerIdentity.PublicKey.Public || m.issuer.PublicKey.Public == m.enrollment.RelaySignerIdentity.PublicKey.Public {
		return errors.New("node-managed authority key purposes must be separate")
	}
	_, err := iscpbridge.VerifiedTLSConfig(m.enrollment.TLSCertificatePEM)
	return err
}

func loadResponderMaterial(cfg Config, m material, controlOnly bool) (material, error) {
	if err := readJSONFile(cfg.IssuerIdentityFile, &m.issuer, false); err != nil {
		return m, errors.New("load pinned node Grant issuer")
	}
	if err := validateNodeAuthorities(cfg, m); err != nil {
		return m, err
	}
	if !controlOnly {
		if err := validateEnrollment(m.enrollment, m.device.Identity, cfg.EffectiveRelayProfile(), time.Now().UTC()); err != nil {
			return m, err
		}
	}
	return m, nil
}
