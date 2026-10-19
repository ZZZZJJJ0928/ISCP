package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	ctl "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodecontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type config struct {
	ControlV2                 bool              `json:"control_v2,omitempty"`
	ControlWriterEpoch        string            `json:"control_writer_epoch,omitempty"`
	ControlBind               string            `json:"control_bind,omitempty"`
	ControlTLSCertificateFile string            `json:"control_tls_certificate_file,omitempty"`
	ControlTLSKeyFile         string            `json:"control_tls_key_file,omitempty"`
	ApprovedScopes            []string          `json:"approved_scopes"`
	SchemaVersion             int               `json:"schema_version"`
	Directory                 string            `json:"directory"`
	DatabaseURLFile           string            `json:"database_url_file"`
	StorageKeyFile            string            `json:"storage_key_file"`
	IssuerIdentityFile        string            `json:"issuer_identity_file"`
	IssuerKeyFile             string            `json:"issuer_key_file"`
	InvitationIdentityFile    string            `json:"invitation_identity_file"`
	InvitationKeyFile         string            `json:"invitation_key_file"`
	TemplateFile              string            `json:"template_file"`
	ManagementSocket          string            `json:"management_socket"`
	ManagementTokenFile       string            `json:"management_token_file"`
	AdminTokenFile            string            `json:"admin_token_file"`
	RegistryPath              string            `json:"registry_path"`
	ControlConfigFile         string            `json:"control_config_file"`
	GrantTTLSeconds           int               `json:"grant_ttl_seconds"`
	MigrationClients          map[string]string `json:"migration_clients,omitempty"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "ISCP node issuer startup/operation failed")
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "private configuration")
	activateHistory := flag.String("activate-control-history", "", "explicit maintenance: original invitation ID for a fresh v2 namespace")
	activateWriter := flag.Bool("activate-control-writer", false, "explicit maintenance: fence legacy issuer writers")
	evidence := flag.String("activation-evidence-sha256", "", "operator supplied maintenance evidence digest")
	create := flag.Bool("create-invitation", false, "create one invitation on private stdout")
	name := flag.String("name", "SparkX", "Client name")
	key := flag.String("idempotency-key", "", "stable request key")
	ttl := flag.Int("ttl-seconds", 900, "invitation TTL")
	scopes := flag.String("scopes", "settings.read,settings.write", "approved comma separated operation scopes")
	flag.Parse()
	maintenance := *activateWriter || *activateHistory != ""
	if *path == "" || flag.NArg() != 0 || *activateWriter && *activateHistory != "" || maintenance && *create || maintenance && !n.ValidActivationEvidence(*evidence) || !maintenance && *evidence != "" {
		return n.ErrInvalid
	}
	var cfg config
	if e := ctl.ReadPrivate(*path, &cfg); e != nil {
		return e
	}
	if cfg.SchemaVersion != 1 || !filepath.IsAbs(cfg.Directory) || *activateHistory != "" && !cfg.ControlV2 || cfg.ControlV2 && !maintenance && !*create && cfg.ControlBind == "" {
		return n.ErrInvalid
	}
	st, e := os.Lstat(cfg.Directory)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return n.ErrInvalid
	}
	signer, e := ctl.LoadSigner(cfg.IssuerIdentityFile, cfg.IssuerKeyFile)
	if e != nil {
		return e
	}
	inviter, e := ctl.LoadSigner(cfg.InvitationIdentityFile, cfg.InvitationKeyFile)
	if e != nil {
		return e
	}
	var template n.Credential
	if e = ctl.ReadPrivate(cfg.TemplateFile, &template); e != nil {
		return e
	}
	dsn, e := ctl.ReadPrivateBytes(cfg.DatabaseURLFile)
	if e != nil {
		return e
	}
	storage, e := ctl.ReadPrivateBytes(cfg.StorageKeyFile)
	if e != nil {
		return e
	}
	storageKey, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(storage)))
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store, e := n.NewPostgresStore(ctx, strings.TrimSpace(string(dsn)), storageKey)
	if e != nil {
		return e
	}
	defer store.Close()
	if *activateWriter {
		return store.ActivateControlWriter(ctx, cfg.ControlWriterEpoch, *evidence)
	}
	if cfg.ControlV2 {
		if e = store.ConfigureControlWriter(ctx, cfg.ControlWriterEpoch); e != nil {
			return e
		}
	}
	token, e := ctl.ReadPrivateBytes(cfg.ManagementTokenFile)
	if e != nil {
		return e
	}
	management, e := n.NewGatewayManagement(cfg.ManagementSocket, strings.TrimSpace(string(token)), n.Binding{DeploymentID: template.DeploymentID, OwnerID: template.OwnerID})
	if e != nil {
		return e
	}
	peer, e := ctl.LoadPeer(cfg.ControlConfigFile, nil)
	if e != nil {
		return e
	}
	var recovery n.ControlRelay
	if cfg.ControlV2 {
		var peerConfig ctl.FileConfig
		if e = ctl.ReadPrivate(cfg.ControlConfigFile, &peerConfig); e != nil {
			return e
		}
		actor, err := bridge.LoadDeviceWithKeyBackend(peerConfig.IdentityFile, peerConfig.KeyFile, peerConfig.KeyBackend, peerConfig.KeyringService)
		if err != nil {
			return err
		}
		recovery, e = ctl.NewHTTPControlRelay(template.Origin, template.TLSCertificatePEM, template.RelayID, actor, template.RelaySignerIdentity)
		if e != nil {
			return e
		}
	}
	issuer, e := n.New(n.Config{EnableControlV2: cfg.ControlV2, ControlRelay: recovery, Template: template, Issuer: signer, InvitationSigner: inviter, GrantTTL: time.Duration(cfg.GrantTTLSeconds) * time.Second, RegistryPath: cfg.RegistryPath, ApprovedScopes: cfg.ApprovedScopes, MigrationClients: cfg.MigrationClients}, store, management, ctl.RemoteRelay{Peer: peer})
	if e != nil {
		return e
	}
	if *activateHistory != "" {
		return issuer.ActivateControlHistory(ctx, *activateHistory, *evidence)
	}
	if *create {
		credential, e := issuer.CreateInvitation(ctx, *name, time.Duration(*ttl)*time.Second, strings.Split(*scopes, ","), *key)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, credential)
		return nil
	}
	if cfg.ControlV2 {
		certificate, err := ctl.ReadPrivateBytes(cfg.ControlTLSCertificateFile)
		if err != nil {
			return err
		}
		key, err := ctl.ReadPrivateBytes(cfg.ControlTLSKeyFile)
		if err != nil {
			return err
		}
		pair, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", cfg.ControlBind)
		if err != nil {
			return err
		}
		defer listener.Close()
		controlServer := &http.Server{Handler: issuer.ControlHandler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
		go func() {
			<-ctx.Done()
			shutdown, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = controlServer.Shutdown(shutdown)
		}()
		go func() {
			if err := controlServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
				cancel()
			}
		}()
	}
	peer.SetHandler(func(c context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
		if method != "issuer.exchange" {
			return nil, n.ErrDenied
		}
		var x n.Exchange
		if n.StrictDecode(raw, &x) != nil {
			return nil, n.ErrInvalid
		}
		out, e := issuer.Exchange(c, x)
		if e != nil {
			return nil, e
		}
		return json.Marshal(out)
	})
	go peer.RunControlRotation(ctx, signer, template.IssuerRoute)
	go peer.Run(ctx)
	go func() {
		timer := time.NewTicker(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				_ = issuer.Reconcile(ctx)
			}
		}
	}()
	admin, e := ctl.ReadPrivateBytes(cfg.AdminTokenFile)
	if e != nil {
		return e
	}
	socket := filepath.Join(cfg.Directory, "issuer.sock")
	listener, e := ctl.ListenPrivateUnix(socket)
	if e != nil {
		return e
	}
	defer os.Remove(socket)
	server := &http.Server{Handler: issuer.ManagementHandler(strings.TrimSpace(string(admin))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = server.Shutdown(shutdown)
	}()
	e = server.Serve(listener)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
