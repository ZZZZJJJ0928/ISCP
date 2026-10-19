package main

import "testing"

func TestListenBoundaryRequiresExplicitLocalContainerOptIn(t *testing.T) {
	for _, tc := range []struct {
		address      string
		allow, valid bool
	}{
		{"127.0.0.1:0", false, true}, {"127.0.0.1:8080", false, true},
		{"0.0.0.0:8080", false, false}, {"0.0.0.0:8080", true, true},
		{"0.0.0.0:8081", true, false}, {"192.168.1.1:8080", true, false},
		{"localhost:8080", false, false}, {"[::]:8080", true, false},
		{"127.0.0.1:65536", false, false}, {"127.0.0.1:-1", false, false},
		{"127.0.0.1:http", false, false},
	} {
		if err := validateListen(tc.address, tc.allow); (err == nil) != tc.valid {
			t.Errorf("%s, allow=%v: %v", tc.address, tc.allow, err)
		}
	}
}
