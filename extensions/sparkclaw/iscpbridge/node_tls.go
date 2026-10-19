package iscpbridge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// VerifiedTLSConfig trusts the public certificate delivered by the Owner's
// signed credential. Standard certificate time, chain and hostname/IP checks
// remain enabled; it neither adds system roots nor skips verification.
func VerifiedTLSConfig(certificatePEM string) (*tls.Config, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > 16<<10 {
		return nil, errors.New("node-managed TLS certificate is invalid")
	}
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 && string(rest) != "\n" {
		return nil, errors.New("node-managed TLS requires one public certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("node-managed TLS certificate is invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}
