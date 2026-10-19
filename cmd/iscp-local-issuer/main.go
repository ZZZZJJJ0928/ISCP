package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscplocalissuer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "local issuer:", err)
		os.Exit(1)
	}
}
func run() error {
	initialize := flag.Bool("init", false, "create a new private local-test issuer")
	directory := flag.String("directory", "", "new absolute private issuer directory")
	subject := flag.String("subject-identity", "", "enrolled SparkX public identity file")
	audience := flag.String("audience-identity", "", "enrolled SparkClaw public identity file")
	relay := flag.String("relay-id", "", "enrolled Relay ID")
	config := flag.String("config", "", "private issuer config")
	authorize := flag.Bool("authorize-renewal", false, "authorize fixed-scope short grant renewal")
	revoke := flag.Bool("revoke-renewal", false, "revoke the existing renewal authorization")
	reauthorize := flag.Bool("reauthorize-permanent", false, "explicitly replace consent with a new revision and export its new Grant")
	expectedRevision := flag.Uint64("expected-revision", 0, "current standing authorization revision for explicit reauthorization")
	operationID := flag.String("operation-id", "", "stable operator reauthorization ID; repeat it to recover the same Grant")
	grantFile := flag.String("grant-file", "", "private current grant file for explicit renewal authorization")
	authorizationScopes := flag.String("authorization-scopes", "", "explicit comma-separated permanent authorization scopes; renewal never widens them")
	authorizationHours := flag.Int("authorization-hours", 0, "0 authorizes until manual deletion; 24 to 8760 retains the legacy bounded policy")
	listen := flag.String("listen", "127.0.0.1:0", "local issuer listen address")
	containerListen := flag.Bool("allow-container-listen", false, "allow local-test container address 0.0.0.0:8080")
	flag.Parse()
	actions := 0
	for _, selected := range []bool{*initialize, *authorize, *revoke, *reauthorize} {
		if selected {
			actions++
		}
	}
	if flag.NArg() != 0 || actions > 1 {
		return errors.New("select exactly one issuer action")
	}
	if *initialize {
		_, err := iscplocalissuer.Initialize(*directory, *subject, *audience, *relay)
		return err
	}
	issuer, err := iscplocalissuer.Load(*config)
	if err != nil {
		return err
	}
	if *reauthorize {
		if !filepath.IsAbs(*grantFile) {
			return errors.New("reauthorization requires an absolute private Grant output path")
		}
		var scopes []string
		if *authorizationScopes != "" {
			scopes = strings.Split(*authorizationScopes, ",")
		}
		grant, err := issuer.ReauthorizePermanentScopes(*operationID, *expectedRevision, scopes)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(grant)
		if err != nil {
			return err
		}
		return writeGrantExport(*grantFile, raw)
	}
	if *authorize {
		if *authorizationHours == 0 {
			var scopes []string
			if *authorizationScopes != "" {
				scopes = strings.Split(*authorizationScopes, ",")
			}
			return issuer.AuthorizePermanentScopes(*grantFile, scopes)
		}
		if *authorizationScopes != "" {
			return errors.New("scopes require permanent authorization")
		}
		return issuer.AuthorizeRenewal(*grantFile, *authorizationHours)
	}
	if *revoke {
		return issuer.RevokeRenewal()
	}
	if err = validateListen(*listen, *containerListen); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Handler: issuer.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		<-ctx.Done()
		closing, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(closing)
	}()
	fmt.Printf("{\"issuer_url\":\"http://%s\"}\n", listener.Addr())
	if err = server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func writeGrantExport(path string, raw []byte) error {
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return errors.New("Grant export target must be private regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".reauthorized-grant-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validateListen(address string, allowContainer bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("issuer listen address must be 127.0.0.1:port")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 0 || value > 65535 {
		return errors.New("invalid issuer listen port")
	}
	if host == "127.0.0.1" {
		return nil
	}
	// Load rejects any config other than local-test before this explicit
	// exception is evaluated. Deployment owns container/network publication.
	if allowContainer && address == "0.0.0.0:8080" {
		return nil
	}
	return errors.New("issuer listen address must be 127.0.0.1:port; local containers require the explicit flag and 0.0.0.0:8080")
}
