package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeclient"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

type enrollmentLocalBinding struct {
	CredentialDigest string `json:"credential_digest"`
	InstallationID   string `json:"installation_id"`
	KeyBackend       string `json:"key_backend"`
	KeyringService   string `json:"keyring_service"`
}
type nodeConnectionDescriptor struct {
	SchemaVersion          int    `json:"schema_version"`
	Transport              string `json:"transport"`
	Mode                   string `json:"mode"`
	TestMode               bool   `json:"test_mode"`
	Origin                 string `json:"origin"`
	DeploymentID           string `json:"deployment_id"`
	OwnerID                string `json:"owner_id"`
	ClientID               string `json:"client_id"`
	DomainID               string `json:"domain_id"`
	InitiatorDeviceID      string `json:"initiator_device_id"`
	ResponderDeviceID      string `json:"responder_device_id"`
	ResponderKeyThumbprint string `json:"responder_key_thumbprint"`
	RelayURL               string `json:"relay_url"`
	RelayProfile           string `json:"relay_profile"`
}

// enrollNode consumes exactly one private stdin line. It persists the native
// identity before network mutation and writes a pending independent profile;
// the caller verifies native business readiness before selecting that profile.
func enrollNode(ctx context.Context, input io.Reader, output io.Writer, directory, backend, keyringService, installation string) error {
	if !filepath.IsAbs(directory) || !uuidPatternCLI(installation) || (backend != iscpbridge.IdentityKeyBackendKeyring && backend != iscpbridge.IdentityKeyBackendFile) {
		return errors.New("enrollment requires private absolute directory, supported key backend and installation UUID")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return errors.New("enrollment directory must be private and regular")
	}
	scanner := bufio.NewScanner(io.LimitReader(input, iscpnodeissuer.MaxCredentialBytes*2))
	scanner.Buffer(make([]byte, 4096), iscpnodeissuer.MaxCredentialBytes*2)
	if !scanner.Scan() {
		return errors.New("missing enrollment credential")
	}
	encoded := scanner.Text()
	if scanner.Scan() || scanner.Err() != nil {
		return errors.New("enrollment accepts exactly one credential line")
	}
	credential, err := iscpnodeissuer.ParseCredential(encoded, time.Now().UTC(), true)
	if err != nil {
		return errors.New("invalid node enrollment credential")
	}
	bind := enrollmentLocalBinding{iscpnodeissuer.Digest(credential), installation, backend, keyringService}
	bindPath := filepath.Join(directory, "enrollment.binding.json")
	if raw, e := os.ReadFile(bindPath); e == nil {
		var old enrollmentLocalBinding
		if iscpnodeissuer.StrictDecode(raw, &old) != nil || old != bind {
			return errors.New("pending enrollment belongs to another credential, installation or native key store")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return errors.New("pending enrollment binding unavailable")
	} else {
		raw, _ := json.Marshal(bind)
		if err = iscpnodeissuer.WritePrivateAtomic(bindPath, raw); err != nil {
			return err
		}
	}
	deviceDir := filepath.Join(directory, "identity")
	identityPath := filepath.Join(deviceDir, iscpbridge.IdentityFileName)
	if _, err := os.Lstat(identityPath); errors.Is(err, os.ErrNotExist) {
		if !time.Now().Before(credential.ExpiresAt) {
			return errors.New("new enrollment credential expired")
		}
		if _, _, err = iscpbridge.GenerateEnrollmentRequestWithKeyBackend(deviceDir, credential.DomainID, "sparkx-"+newHelperUUID(), "desktop", backend, keyringService, time.Now().UTC()); err != nil {
			return errors.New("native device key creation failed")
		}
	} else if err != nil {
		return errors.New("native device identity unavailable")
	}
	device, err := iscpbridge.LoadDeviceWithKeyBackend(identityPath, filepath.Join(deviceDir, iscpbridge.IdentityKeyFileName), backend, keyringService)
	if err != nil || device.Identity.DomainID != credential.DomainID {
		return errors.New("native device key loading failed")
	}
	client, err := iscpnodeclient.New(encoded, device, filepath.Join(deviceDir, "node-control"))
	if err != nil {
		return errors.New("node enrollment initialization failed")
	}
	if err = client.SetInstallationID(installation); err != nil {
		return err
	}
	result, err := client.Enroll(ctx)
	if err != nil {
		return err
	}
	if result.InstallationID != installation {
		return errors.New("issuer result differs from local installation")
	}
	paths := map[string]any{"relay.enrollment.json": result.Enrollment, "grant.json": result.Grant, "peer.identity.json": result.ResponderIdentity, "issuer.identity.json": result.IssuerIdentity, "invitation.identity.json": result.InvitationSignerIdentity, "issuer.control.json": client.StoredConfig()}
	for name, value := range paths {
		raw, e := json.Marshal(value)
		if e != nil {
			return e
		}
		if e = iscpnodeissuer.WritePrivateAtomic(filepath.Join(directory, name), raw); e != nil {
			return e
		}
	}
	cfg := iscpworkbench.Config{ExpectedInstallationID: installation, SchemaVersion: 2, Mode: "node-managed", Role: iscpworkbench.RoleInitiator, RelayProfile: iscpbridge.ProfileProduction, ApplicationProfiles: []string{iscpworkbench.Profile, iscpworkbench.ProfileV2}, IdentityDirectory: deviceDir, IdentityKeyBackend: backend, IdentityKeyringService: keyringService, EnrollmentFile: filepath.Join(directory, "relay.enrollment.json"), PeerIdentityFile: filepath.Join(directory, "peer.identity.json"), IssuerIdentityFile: filepath.Join(directory, "issuer.identity.json"), InvitationIdentityFile: filepath.Join(directory, "invitation.identity.json"), IssuerControlFile: filepath.Join(directory, "issuer.control.json"), GrantFile: filepath.Join(directory, "grant.json"), Binding: &iscpworkbench.Binding{DeploymentID: result.Binding.DeploymentID, OwnerID: result.Binding.OwnerID, ClientID: result.Binding.ClientID}}
	helperPath := filepath.Join(directory, "workbench.json")
	raw, _ := json.Marshal(cfg)
	if err = iscpnodeissuer.WritePrivateAtomic(helperPath, raw); err != nil {
		return err
	}
	if !time.Now().Before(result.Grant.ExpiresAt) || !time.Now().Before(result.Enrollment.Access.ExpiresAt) || !time.Now().Before(result.Enrollment.Refresh.ExpiresAt) || !time.Now().Before(result.Enrollment.ExpiresAt) {
		if _, err = iscpworkbench.RecoverNodeEnrollment(ctx, helperPath); err != nil {
			return err
		}
	}
	if _, err = iscpworkbench.LoadConfig(helperPath); err != nil {
		return errors.New("node-managed enrollment result failed private runtime validation")
	}
	descriptor := nodeConnectionDescriptor{4, "iscp", "node-managed", false, "https://iscp.invalid", result.Binding.DeploymentID, result.Binding.OwnerID, result.Binding.ClientID, result.Identity.DomainID, result.Identity.DeviceID, result.ResponderIdentity.DeviceID, result.ResponderIdentity.PublicKey.KID, result.Enrollment.RelayBaseURL, iscpbridge.ProfileProduction}
	profilePath := filepath.Join(directory, "connection.profile.json")
	raw, _ = json.Marshal(struct {
		SchemaVersion int                      `json:"schema_version"`
		Transport     string                   `json:"transport"`
		Mode          string                   `json:"mode"`
		Backend       nodeConnectionDescriptor `json:"backend"`
		HelperConfig  string                   `json:"helper_config"`
	}{2, "iscp", "node-managed", descriptor, helperPath})
	if err = iscpnodeissuer.WritePrivateAtomic(profilePath, raw); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		IPCVersion  int                      `json:"ipc_version"`
		Type        string                   `json:"type"`
		ProfilePath string                   `json:"profile_path"`
		Descriptor  nodeConnectionDescriptor `json:"descriptor"`
	}{1, "enrollment", profilePath, descriptor})
}

var helperUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func uuidPatternCLI(s string) bool { return helperUUIDPattern.MatchString(s) }
func newHelperUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("secure random unavailable")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
