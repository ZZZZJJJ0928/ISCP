// iscp-node-provision creates host-owned identities and operator bootstrap
// requests. Private material is written only to protected files, never stdout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	ctl "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodecontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "private node provisioning failed")
		os.Exit(1)
	}
}
func save(path string, v any) error {
	if !filepath.IsAbs(path) {
		return node.ErrInvalid
	}
	st, e := os.Lstat(filepath.Dir(path))
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return node.ErrInvalid
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(append(b, '\n')); e != nil {
		return e
	}
	return f.Sync()
}
func run() error {
	mode := flag.String("mode", "", "init, proof, control-grant or operator-bind")
	dir := flag.String("directory", "", "private device directory")
	domain := flag.String("domain", "infinimesh-public", "Domain")
	id := flag.String("device", "", "Device")
	role := flag.String("role", "", "Device purpose")
	audience := flag.String("audience", "", "Pinned audience")
	challenge := flag.String("challenge", "", "Fresh public challenge")
	subjectFile := flag.String("subject-file", "", "Pinned subject identity")
	output := flag.String("output", "", "Private output file")
	requestFile := flag.String("request-file", "", "Signed bootstrap request")
	tokenFile := flag.String("admin-token-file", "", "TEST1 operator token file")
	relay := flag.String("relay", "relay-210-16-177-239", "Relay")
	flag.Parse()
	if flag.NArg() != 0 {
		return node.ErrInvalid
	}
	if *mode == "init" {
		if !filepath.IsAbs(*dir) || *id == "" || *role == "" {
			return node.ErrInvalid
		}
		if e := os.MkdirAll(*dir, 0700); e != nil {
			return e
		}
		st, e := os.Lstat(*dir)
		if e != nil || st.Mode().Perm()&0077 != 0 {
			return node.ErrInvalid
		}
		d, e := identity.NewDevice(c.NewProvider(), *domain, *id, time.Now().UTC())
		if e != nil {
			return e
		}
		d.Identity.Metadata = map[string]string{"product_kind": "sparkclaw", "device_role": *role}
		if e = save(filepath.Join(*dir, bridge.IdentityFileName), d.Identity); e != nil {
			return e
		}
		f, e := os.OpenFile(filepath.Join(*dir, bridge.IdentityKeyFileName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = f.WriteString(c.Base64URL(d.Private.BytesForDevStore()))
		if e != nil {
			return e
		}
		return f.Sync()
	}
	if *mode == "operator-bind" {
		var request struct {
			Identity identity.DeviceIdentity `json:"identity"`
			Proof    identity.DeviceProof    `json:"proof"`
		}
		if e := ctl.ReadPrivate(*requestFile, &request); e != nil {
			return e
		}
		if request.Identity.DomainID != *domain || identity.VerifyProof(c.NewProvider(), request.Identity, request.Proof, *relay, request.Proof.Challenge, time.Now().UTC(), time.Minute) != nil {
			return node.ErrDenied
		}
		token, e := ctl.ReadPrivateBytes(*tokenFile)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(request)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, e := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:55117/v2/relay/devices/bind-self", bytes.NewReader(raw))
		if e != nil {
			return e
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		cli := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect prohibited") }}
		res, e := cli.Do(req)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 32<<10))
		if e != nil || res.StatusCode != 200 && res.StatusCode != 201 {
			return node.ErrDenied
		}
		var out any
		if e = json.Unmarshal(b, &out); e != nil {
			return e
		}
		return save(*output, out)
	}
	d, e := ctl.LoadSigner(filepath.Join(*dir, bridge.IdentityFileName), filepath.Join(*dir, bridge.IdentityKeyFileName))
	if e != nil {
		return e
	}
	switch *mode {
	case "proof":
		if *audience == "" || *challenge == "" {
			return node.ErrInvalid
		}
		p, e := d.CreateProof(c.NewProvider(), *audience, *challenge, c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
		if e != nil {
			return e
		}
		return save(*output, map[string]any{"identity": d.Identity, "proof": p})
	case "control-grant":
		var subject identity.DeviceIdentity
		if e = ctl.ReadPrivate(*subjectFile, &subject); e != nil {
			return e
		}
		if subject.DomainID != d.Identity.DomainID || *audience == "" {
			return node.ErrDenied
		}
		now := time.Now().UTC()
		g, e := trust.SignGrant(c.NewProvider(), d, trust.Grant{GrantID: "control-" + c.Base64URL(c.RandomBytes(18)), SubjectDeviceID: subject.DeviceID, Audience: *audience, ConfirmationThumbprint: subject.PublicKey.KID, Permissions: []string{ctl.ControlPermission}, RelayConstraints: []string{*relay}, NotBefore: now, ExpiresAt: now.Add(7 * 24 * time.Hour), RevocationEpoch: 1})
		if e != nil {
			return e
		}
		return save(*output, g)
	default:
		return node.ErrInvalid
	}
}
