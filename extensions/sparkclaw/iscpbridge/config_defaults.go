package iscpbridge

import "time"

// Kept from SparkClaw gateway_client.go for Config normalization. The Gateway
// business HTTP client itself stays in SparkClaw and is not part of this SDK.
const (
	defaultGatewayURL     = "http://127.0.0.1:18789"
	defaultGatewayTimeout = 30 * time.Second
)
