package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscplocalenroll"
)

func main() {
	var opts iscplocalenroll.Options
	flag.StringVar(&opts.RelayURL, "relay-url", "", "loopback HTTP discovery and enrollment URL")
	flag.StringVar(&opts.RelayID, "relay-id", "", "expected local reference Relay ID")
	flag.StringVar(&opts.DomainID, "domain-id", "", "expected local reference Domain ID")
	flag.StringVar(&opts.DeviceID, "device-id", "", "independent device ID")
	flag.StringVar(&opts.IdentityDirectory, "identity-dir", "", "private device identity directory")
	flag.StringVar(&opts.EnrollmentFile, "enrollment-file", "", "private enrollment output file")
	flag.StringVar(&opts.RuntimeRelayURL, "runtime-relay-url", "", "optional host/container local Relay alias")
	flag.StringVar(&opts.RuntimeWebSocketURL, "runtime-websocket-url", "", "optional host/container WebSocket alias")
	refresh := flag.Bool("refresh-existing", false, "refresh the existing pinned local Relay enrollment without enrollment or identity creation")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected enrollment arguments")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var summary iscplocalenroll.Summary
	var err error
	if *refresh {
		summary, err = iscplocalenroll.Refresh(ctx, opts)
	} else {
		summary, err = iscplocalenroll.Enroll(ctx, opts)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "local ISCP enrollment failed:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		os.Exit(1)
	}
}
