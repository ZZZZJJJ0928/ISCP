package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	ctl "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodecontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type config struct {
	ApprovedScopes         []string          `json:"approved_scopes"`
	SchemaVersion          int               `json:"schema_version"`
	Directory              string            `json:"directory"`
	DatabaseURLFile        string            `json:"database_url_file"`
	StorageKeyFile         string            `json:"storage_key_file"`
	IssuerIdentityFile     string            `json:"issuer_identity_file"`
	IssuerKeyFile          string            `json:"issuer_key_file"`
	InvitationIdentityFile string            `json:"invitation_identity_file"`
	InvitationKeyFile      string            `json:"invitation_key_file"`
	TemplateFile           string            `json:"template_file"`
	ManagementSocket       string            `json:"management_socket"`
	ManagementTokenFile    string            `json:"management_token_file"`
	AdminTokenFile         string            `json:"admin_token_file"`
	RegistryPath           string            `json:"registry_path"`
	ControlConfigFile      string            `json:"control_config_file"`
	GrantTTLSeconds        int               `json:"grant_ttl_seconds"`
	MigrationClients       map[string]string `json:"migration_clients,omitempty"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "ISCP node issuer startup/operation failed")
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "private configuration")
	create := flag.Bool("create-invitation", false, "create one invitation on private stdout")
	name := flag.String("name", "SparkX", "Client name")
	key := flag.String("idempotency-key", "", "stable request key")
	ttl := flag.Int("ttl-seconds", 900, "invitation TTL")
	scopes := flag.String("scopes", "settings.read,settings.write", "approved comma separated operation scopes")
	flag.Parse()
	var cfg config
	if e := ctl.ReadPrivate(*path, &cfg); e != nil {
		return e
	}
	if cfg.SchemaVersion != 1 || !filepath.IsAbs(cfg.Directory) {
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
	issuer, e := n.New(n.Config{Template: template, Issuer: signer, InvitationSigner: inviter, GrantTTL: time.Duration(cfg.GrantTTLSeconds) * time.Second, RegistryPath: cfg.RegistryPath, ApprovedScopes: cfg.ApprovedScopes, MigrationClients: cfg.MigrationClients}, store, management, ctl.RemoteRelay{Peer: peer})
	if e != nil {
		return e
	}
	if *create {
		credential, e := issuer.CreateInvitation(ctx, *name, time.Duration(*ttl)*time.Second, strings.Split(*scopes, ","), *key)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, credential)
		return nil
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
