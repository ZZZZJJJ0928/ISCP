package iscpworkbench

import (
	"embed"
	"encoding/json"
	"slices"
)

//go:embed operations.json
var registryFiles embed.FS

type OperationSpec struct {
	CapacityClass string         `json:"capacity_class"`
	Name          string         `json:"name"`
	Constant      string         `json:"constant"`
	Version       int            `json:"version"`
	Direction     string         `json:"direction"`
	Scope         string         `json:"scope"`
	Mutation      bool           `json:"mutation"`
	Recovery      string         `json:"recovery"`
	LimitBytes    int            `json:"limit_bytes"`
	Dependencies  []string       `json:"dependencies"`
	Params        []string       `json:"params"`
	HTTP          *OperationHTTP `json:"http,omitempty"`
}
type OperationHTTP struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

var operationRegistry = func() []OperationSpec {
	raw, err := registryFiles.ReadFile("operations.json")
	if err != nil {
		panic(err)
	}
	var specs []OperationSpec
	if err = json.Unmarshal(raw, &specs); err != nil {
		panic(err)
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if s.Name == "" || seen[s.Name] || (s.Version != 1 && s.Version != 2) || s.Scope == "" || (s.Direction != "forward" && s.Direction != "reverse") {
			panic("invalid operation registry")
		}
		seen[s.Name] = true
	}
	return specs
}()

func OperationRegistry() []OperationSpec {
	out := append([]OperationSpec(nil), operationRegistry...)
	for i := range out {
		out[i].Params = slices.Clone(out[i].Params)
		out[i].Dependencies = slices.Clone(out[i].Dependencies)
		if out[i].HTTP != nil {
			h := *out[i].HTTP
			out[i].HTTP = &h
		}
	}
	return out
}
func LookupOperation(name string) (OperationSpec, bool) {
	for _, s := range OperationRegistry() {
		if s.Name == name {
			return s, true
		}
	}
	return OperationSpec{}, false
}
func Operations() []string {
	var out []string
	for _, s := range operationRegistry {
		if s.Version == 1 {
			out = append(out, s.Name)
		}
	}
	return out
}
func OperationsV2() []string {
	var out []string
	for _, s := range operationRegistry {
		out = append(out, s.Name)
	}
	return out
}

// Local-test preserves the operation table understood by existing installed
// helpers. Node-managed clients negotiate the explicitly extended app table.
func OperationsV2ForMode(mode string) []string {
	ops := OperationsV2()
	if mode == "local-test" {
		ops = slices.DeleteFunc(ops, func(name string) bool {
			return name == OperationClientsList || name == OperationClientsIssue || name == OperationClientsRevoke || name == OperationClientsDelete
		})
	}
	return ops
}

// CapacityLimit describes old peers' fixed per-class limits. Newly negotiated
// unbounded RPC does not acquire these slots; priority and byte limits remain.
func CapacityLimit(class string) int {
	switch class {
	case "control", "events":
		return 1
	case "bulk", "audio":
		return 2
	default:
		return MaxConcurrent
	}
}
func OperationCapacity(name string) (string, int) {
	spec, ok := LookupOperation(name)
	if !ok {
		return "business", MaxConcurrent
	}
	return spec.CapacityClass, CapacityLimit(spec.CapacityClass)
}

type capacityContextKey struct{}

func capacityPriority(class string) int {
	switch class {
	case "control":
		return 9
	case "audio":
		return 7
	case "events":
		return 6
	case "bulk":
		return 1
	default:
		return 5
	}
}
