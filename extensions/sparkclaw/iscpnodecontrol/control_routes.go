package iscpnodecontrol

import (
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"net/http"
)

type HTTPSControlRoute struct {
	Audience           string `json:"audience"`
	Origin             string `json:"origin"`
	TLSCertificateFile string `json:"tls_certificate_file"`
}

func LoadHTTPSControlRoutes(path string, local map[string]http.Handler) (*control.Router, error) {
	targets := map[string]http.Handler{}
	for id, h := range local {
		targets[id] = h
	}
	if path != "" {
		var routes []HTTPSControlRoute
		if err := ReadPrivate(path, &routes); err != nil {
			return nil, err
		}
		for _, route := range routes {
			if route.Audience == "" || targets[route.Audience] != nil {
				return nil, n.ErrInvalid
			}
			cert, err := ReadPrivateBytes(route.TLSCertificateFile)
			if err != nil {
				return nil, err
			}
			target, err := NewHTTPSControlTarget(route.Origin, string(cert))
			if err != nil {
				return nil, err
			}
			targets[route.Audience] = target
		}
	}
	return control.NewRouter(targets)
}
