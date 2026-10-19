package main

import (
	"context"
	"flag"
	"fmt"
	ctl "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodecontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "ISCP control forwarder startup failed")
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "private configuration")
	flag.Parse()
	var cfg ctl.ForwarderConfig
	if e := ctl.ReadPrivate(*path, &cfg); e != nil {
		return e
	}
	if e := cfg.Validate(); e != nil {
		return n.ErrInvalid
	}
	var peers []*ctl.Peer
	var forwarders []*ctl.Forwarder
	for _, node := range cfg.NodeConfigs() {
		adapter, e := ctl.NewUnixRelay(node.RelaySocket)
		if e != nil {
			return e
		}
		peer, e := ctl.LoadPeer(node.PeerConfigFile, nil)
		if e != nil {
			return e
		}
		forwarder, e := ctl.NewForwarder(node.IssuerRoute, peer, adapter)
		if e != nil {
			return e
		}
		peer.SetHandler(forwarder.PrivateHandler)
		peers = append(peers, peer)
		forwarders = append(forwarders, forwarder)
	}
	if e := ctl.ValidatePeerSet(peers); e != nil {
		return e
	}
	handler, e := ctl.NewForwarderRouter(forwarders)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for _, peer := range peers {
		go peer.Run(ctx)
	}
	listener, e := net.Listen("tcp", cfg.Bind)
	if e != nil {
		return e
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
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
