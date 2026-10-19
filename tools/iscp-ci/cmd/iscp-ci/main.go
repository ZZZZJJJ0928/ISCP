package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
)

type schemaManifestEntry struct {
	File       string
	ObjectType string
}

var expectedSchemas = []schemaManifestEntry{
	{File: "delivery_receipt.v2.json", ObjectType: "iscp.delivery_receipt.v2"},
	{File: "device.identity.v2.json", ObjectType: "iscp.device.identity.v2"},
	{File: "device.proof.v2.json", ObjectType: "iscp.device.proof.v2"},
	{File: "error.v2.json", ObjectType: "iscp.error.v2"},
	{File: "pairing_ticket.v2.json", ObjectType: "iscp.pairing_ticket.v2"},
	{File: "pairing_ticket.v3.json", ObjectType: "iscp.pairing_ticket.v3"},
	{File: "provisioning.bundle.v2.json", ObjectType: "iscp.provisioning.bundle.v2"},
	{File: "relay.credential_recovery.wrapped.v2.json", ObjectType: "iscp.relay.credential_recovery.wrapped.v2"},
	{File: "relay.descriptor.v2.json", ObjectType: "iscp.relay.descriptor.v2"},
	{File: "secure_envelope.v2.json", ObjectType: "iscp.secure_envelope.v2"},
	{File: "session.close.v1.json", ObjectType: "iscp.session.close.v1"},
	{File: "session.hello.v2.json", ObjectType: "iscp.session.hello.v2"},
	{File: "session.ready.v2.json", ObjectType: "iscp.session.ready.v2"},
	{File: "session.reopen.v1.json", ObjectType: "iscp.session.reopen.v1"},
	{File: "signed_descriptor.v2.json", ObjectType: "iscp.signed_descriptor.v2"},
	{File: "trust.device_status.v2.json", ObjectType: "iscp.trust.device_status.v2"},
	{File: "trust.grant_status.v2.json", ObjectType: "iscp.trust.grant_status.v2"},
	{File: "trust.revocations.v2.json", ObjectType: "iscp.trust.revocations.v2"},
	{File: "trust_grant.v2.json", ObjectType: "iscp.trust_grant.v2"},
	{File: "trust_root.descriptor.v2.json", ObjectType: "iscp.trust_root.descriptor.v2"},
}

var signedSchemas = map[string]bool{
	"device.proof.v2.json":        true,
	"pairing_ticket.v2.json":      true,
	"pairing_ticket.v3.json":      true,
	"provisioning.bundle.v2.json": true,
	"session.close.v1.json":       true,
	"session.hello.v2.json":       true,
	"session.ready.v2.json":       true,
	"session.reopen.v1.json":      true,
	"signed_descriptor.v2.json":   true,
	"trust_grant.v2.json":         true,
}

type methodManifestEntry struct {
	Path   string `json:"path"`
	Method string `json:"method"`
}

var expectedMethods = []methodManifestEntry{
	{Path: "/.well-known/iscp/relay", Method: "get"},
	{Path: "/v2/relay/devices/bind-self", Method: "post"},
	{Path: "/v2/relay/devices/register-with-ticket", Method: "post"},
	{Path: "/v2/relay/devices/refresh-access", Method: "post"},
	{Path: "/v2/relay/devices/revoke-access", Method: "post"},
	{Path: "/v2/relay/connect", Method: "get"},
	{Path: "/v2/relay/envelopes", Method: "post"},
	{Path: "/v2/relay/admin/devices", Method: "get"},
	{Path: "/v2/relay/admin/connections", Method: "get"},
	{Path: "/v2/relay/admin/messages", Method: "get"},
	{Path: "/api/sparkclaw/iscp-control/v1/service-recover", Method: "post"},
	{Path: "/.well-known/iscp/trust-root", Method: "get"},
	{Path: "/v2/trust/devices/submit", Method: "post"},
	{Path: "/v2/trust/devices/authorize", Method: "post"},
	{Path: "/v2/trust/devices/revoke", Method: "post"},
	{Path: "/v2/trust/devices/status", Method: "get"},
	{Path: "/v2/trust/grants/verify", Method: "post"},
	{Path: "/v2/trust/grants/status", Method: "get"},
	{Path: "/v2/trust/grants/revoke", Method: "post"},
	{Path: "/v2/trust/revocations", Method: "get"},
	{Path: "/v2/trust/keys/rotate", Method: "post"},
	{Path: "/v2/trust/admin/audit", Method: "get"},
}

type schemaResult struct {
	File          string   `json:"file"`
	ID            *string  `json:"id,omitempty"`
	ObjectType    string   `json:"object_type"`
	RequiredCount int      `json:"required_count,omitempty"`
	Status        string   `json:"status"`
	Errors        []string `json:"errors"`
}

type schemaSummary struct {
	Type                string         `json:"type"`
	GeneratedAt         string         `json:"generated_at"`
	SchemaDir           string         `json:"schema_dir"`
	Status              string         `json:"status"`
	ExpectedSchemaCount int            `json:"expected_schema_count"`
	CheckedSchemaCount  int            `json:"checked_schema_count"`
	MissingSchemas      []string       `json:"missing_schemas"`
	UnexpectedSchemas   []string       `json:"unexpected_schemas"`
	Schemas             []schemaResult `json:"schemas"`
	Errors              []string       `json:"errors"`
}

type openAPISummary struct {
	Type                     string                `json:"type"`
	GeneratedAt              string                `json:"generated_at"`
	OpenAPIFile              string                `json:"openapi_file"`
	RouteSources             []string              `json:"route_sources"`
	Status                   string                `json:"status"`
	OpenAPIPathCount         int                   `json:"openapi_path_count"`
	ServiceRouteCount        int                   `json:"service_route_count"`
	CheckedPaths             []methodManifestEntry `json:"checked_paths"`
	MissingFromOpenAPI       []string              `json:"missing_from_openapi"`
	NotImplementedByServices []string              `json:"not_implemented_by_services"`
	Errors                   []string              `json:"errors"`
}

type cyclonedxBOM struct {
	BOMFormat   string             `json:"bomFormat"`
	SpecVersion string             `json:"specVersion"`
	Version     int                `json:"version"`
	Metadata    cyclonedxMetadata  `json:"metadata"`
	Components  []cyclonedxLibrary `json:"components"`
}

type cyclonedxMetadata struct {
	Component cyclonedxComponent `json:"component"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cyclonedxLibrary struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: iscp-ci <generate-schemas|generate-openapi|traceability|helm-check|postgres-check|sbom>")
		os.Exit(2)
	}

	rootPath, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer root.Close()

	switch os.Args[1] {
	case "generate-schemas":
		err = generateSchemas(root)
	case "generate-openapi":
		err = generateOpenAPI(root)
	case "traceability":
		err = validateTraceability(root)
	case "helm-check":
		err = validateHelm(root, rootPath)
	case "postgres-check":
		err = validatePostgres(root)
	case "sbom":
		err = generateSBOM(root)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type traceabilityRow struct {
	ID          string `json:"id"`
	Requirement string `json:"requirement"`
	Evidence    string `json:"evidence"`
	Status      string `json:"status"`
}

type traceabilitySummary struct {
	Type                string            `json:"type"`
	GeneratedAt         string            `json:"generated_at"`
	SpecFile            string            `json:"spec_file"`
	MatrixFile          string            `json:"matrix_file"`
	Status              string            `json:"status"`
	RequirementCount    int               `json:"requirement_count"`
	MatrixRowCount      int               `json:"matrix_row_count"`
	MissingRequirements []string          `json:"missing_requirements"`
	ExtraRequirements   []string          `json:"extra_requirements"`
	DuplicateIDs        []string          `json:"duplicate_ids"`
	Rows                []traceabilityRow `json:"rows"`
	Errors              []string          `json:"errors"`
}

type helmSummary struct {
	Type         string   `json:"type"`
	GeneratedAt  string   `json:"generated_at"`
	ChartDir     string   `json:"chart_dir"`
	Status       string   `json:"status"`
	CheckedFiles []string `json:"checked_files"`
	Errors       []string `json:"errors"`
}

type postgresSummary struct {
	Type          string   `json:"type"`
	GeneratedAt   string   `json:"generated_at"`
	Status        string   `json:"status"`
	DSNConfigured bool     `json:"dsn_configured"`
	CheckedTables []string `json:"checked_tables"`
	ReplayChecks  []string `json:"replay_checks"`
	QueueChecks   []string `json:"queue_checks"`
	Errors        []string `json:"errors"`
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", errors.New("could not locate repository root containing go.mod")
		}
		wd = parent
	}
}

func generateSchemas(root *os.Root) error {
	errorsOut := []string{}
	results := []schemaResult{}
	idSeen := map[string]string{}
	typeSeen := map[string]string{}

	files := []string{}
	if entries, err := fs.ReadDir(root.FS(), "schemas/json"); err != nil {
		if os.IsNotExist(err) {
			errorsOut = append(errorsOut, "schemas/json directory is missing")
		} else {
			errorsOut = append(errorsOut, fmt.Sprintf("schemas/json cannot be read: %v", err))
		}
	} else {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				files = append(files, entry.Name())
			}
		}
	}
	sort.Strings(files)

	expectedByFile := map[string]string{}
	expectedNames := make([]string, 0, len(expectedSchemas))
	for _, entry := range expectedSchemas {
		expectedByFile[entry.File] = entry.ObjectType
		expectedNames = append(expectedNames, entry.File)
	}

	missingSchemas := difference(expectedNames, files)
	unexpectedSchemas := difference(files, expectedNames)
	if len(missingSchemas) > 0 {
		errorsOut = append(errorsOut, "required JSON Schemas are missing: "+strings.Join(missingSchemas, ", "))
	}
	if len(unexpectedSchemas) > 0 {
		errorsOut = append(errorsOut, "schemas/json contains files not in the schema manifest: "+strings.Join(unexpectedSchemas, ", "))
	}

	for _, entry := range expectedSchemas {
		name := entry.File
		if contains(missingSchemas, name) {
			continue
		}

		schemaErrors := []string{}
		raw, err := root.ReadFile(filepath.Join("schemas", "json", name))
		if err != nil {
			schemaErrors = append(schemaErrors, "invalid JSON: "+err.Error())
			errorsOut = append(errorsOut, name+" invalid JSON")
			results = append(results, schemaResult{File: name, ObjectType: entry.ObjectType, Status: "fail", Errors: schemaErrors})
			continue
		}

		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			schemaErrors = append(schemaErrors, "invalid JSON: "+err.Error())
			errorsOut = append(errorsOut, name+" invalid JSON")
			results = append(results, schemaResult{File: name, ObjectType: entry.ObjectType, Status: "fail", Errors: schemaErrors})
			continue
		}

		schema := stringProperty(doc, "$schema")
		id := stringProperty(doc, "$id")
		title := stringProperty(doc, "title")
		kind := stringProperty(doc, "type")
		additionalProperties, additionalOK := doc["additionalProperties"].(bool)
		required := stringArrayProperty(doc, "required")
		properties := objectProperty(doc, "properties")
		typeProperty := objectProperty(properties, "type")
		typeConst := stringProperty(typeProperty, "const")
		expectedType := expectedByFile[name]
		expectedID := "https://schemas.iscp.dev/json/" + name

		if schema == nil || *schema != "https://json-schema.org/draft/2020-12/schema" {
			schemaErrors = append(schemaErrors, "must use JSON Schema draft 2020-12")
		}
		if id == nil || *id != expectedID {
			schemaErrors = append(schemaErrors, "$id must be "+expectedID)
		}
		if title == nil || strings.TrimSpace(*title) == "" {
			schemaErrors = append(schemaErrors, "title is required")
		}
		if kind == nil || *kind != "object" {
			schemaErrors = append(schemaErrors, "top-level type must be object")
		}
		if !additionalOK || additionalProperties {
			schemaErrors = append(schemaErrors, "top-level additionalProperties must be false")
		}
		if !contains(required, "type") {
			schemaErrors = append(schemaErrors, "required must include type")
		}
		if typeConst == nil || *typeConst != expectedType {
			schemaErrors = append(schemaErrors, "properties.type.const must be "+expectedType)
		}
		if id != nil {
			if previous, ok := idSeen[*id]; ok {
				schemaErrors = append(schemaErrors, "$id duplicates "+previous)
			} else {
				idSeen[*id] = name
			}
		}
		if typeConst != nil {
			if previous, ok := typeSeen[*typeConst]; ok {
				schemaErrors = append(schemaErrors, "object type duplicates "+previous)
			} else {
				typeSeen[*typeConst] = name
			}
		}

		_, signaturePropertyExists := properties["signature"]
		if signedSchemas[name] && !contains(required, "signature") {
			schemaErrors = append(schemaErrors, "signed schema must require signature")
		}
		if signedSchemas[name] || signaturePropertyExists {
			defs := objectProperty(doc, "$defs")
			signatureDef := objectProperty(defs, "signature")
			if signatureDef == nil {
				schemaErrors = append(schemaErrors, "signature property must reference a $defs.signature definition")
			} else {
				signatureRequired := stringArrayProperty(signatureDef, "required")
				signatureProperties := objectProperty(signatureDef, "properties")
				algProperty := objectProperty(signatureProperties, "alg")
				valueProperty := objectProperty(signatureProperties, "value")
				for _, field := range []string{"alg", "kid", "value"} {
					if !contains(signatureRequired, field) {
						schemaErrors = append(schemaErrors, "$defs.signature.required must include "+field)
					}
				}
				algConst := stringProperty(algProperty, "const")
				if algConst == nil || *algConst != "Ed25519" {
					schemaErrors = append(schemaErrors, "$defs.signature.properties.alg.const must be Ed25519")
				}
				valueEncoding := stringProperty(valueProperty, "contentEncoding")
				if valueEncoding == nil || *valueEncoding != "base64url" {
					schemaErrors = append(schemaErrors, "$defs.signature.properties.value.contentEncoding must be base64url")
				}
			}
		}

		if len(schemaErrors) > 0 {
			errorsOut = append(errorsOut, name+" failed schema validation")
		}
		status := "pass"
		if len(schemaErrors) > 0 {
			status = "fail"
		}
		result := schemaResult{
			File:          name,
			ID:            id,
			ObjectType:    expectedType,
			RequiredCount: len(required),
			Status:        status,
			Errors:        schemaErrors,
		}
		results = append(results, result)
	}

	status := "pass"
	if len(errorsOut) > 0 {
		status = "fail"
	}
	summary := schemaSummary{
		Type:                "iscp.schema.validation.v2",
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		SchemaDir:           "schemas/json",
		Status:              status,
		ExpectedSchemaCount: len(expectedSchemas),
		CheckedSchemaCount:  len(results),
		MissingSchemas:      missingSchemas,
		UnexpectedSchemas:   unexpectedSchemas,
		Schemas:             results,
		Errors:              errorsOut,
	}
	if err := writeJSON(root, "dist/schema-check.json", summary); err != nil {
		return err
	}
	if len(errorsOut) > 0 {
		return errors.New("JSON Schema validation failed; see dist/schema-check.json")
	}
	fmt.Println("JSON Schema validation passed; see dist/schema-check.json")
	return nil
}

func generateOpenAPI(root *os.Root) error {
	routeSourceNames := []string{
		"pkg/server/relay/server.go",
		"services/trust-root-reference/internal/trust/server.go",
	}

	errorsOut := []string{}
	content := ""
	openAPIPaths := []string{}
	if raw, err := root.ReadFile(filepath.Join("docs", "api", "openapi.yaml")); err != nil {
		if os.IsNotExist(err) {
			errorsOut = append(errorsOut, "docs/api/openapi.yaml is missing")
		} else {
			errorsOut = append(errorsOut, fmt.Sprintf("docs/api/openapi.yaml cannot be read: %v", err))
		}
	} else {
		content = string(raw)
		if !regexp.MustCompile(`(?m)^openapi:\s*3\.1\.0\s*$`).MatchString(content) {
			errorsOut = append(errorsOut, "docs/api/openapi.yaml must declare openapi: 3.1.0")
		}
		if !regexp.MustCompile(`(?m)^components:\s*$`).MatchString(content) ||
			!regexp.MustCompile(`(?m)^  schemas:\s*$`).MatchString(content) ||
			!regexp.MustCompile(`(?m)^    Error:\s*$`).MatchString(content) {
			errorsOut = append(errorsOut, "docs/api/openapi.yaml must include components.schemas.Error")
		}
		openAPIPaths = extractOpenAPIPaths(content)
		if len(openAPIPaths) == 0 {
			errorsOut = append(errorsOut, "docs/api/openapi.yaml has no path entries")
		}
	}

	serviceRoutes := []string{}
	routeRe := regexp.MustCompile(`HandleFunc\("([^"]+)"`)
	for _, routeSourceName := range routeSourceNames {
		raw, err := root.ReadFile(filepath.FromSlash(routeSourceName))
		if err != nil {
			errorsOut = append(errorsOut, "route source file is missing: "+routeSourceName)
			continue
		}
		for _, match := range routeRe.FindAllStringSubmatch(string(raw), -1) {
			serviceRoutes = append(serviceRoutes, match[1])
		}
	}

	publicServiceRoutes := publicRoutes(serviceRoutes)
	openAPIPublicPaths := publicRoutes(openAPIPaths)
	expectedPaths := make([]string, 0, len(expectedMethods))
	methodByPath := map[string]string{}
	for _, entry := range expectedMethods {
		expectedPaths = append(expectedPaths, entry.Path)
		methodByPath[entry.Path] = entry.Method
	}

	missingFromOpenAPI := difference(publicServiceRoutes, openAPIPaths)
	notImplementedByServices := difference(openAPIPublicPaths, publicServiceRoutes)
	missingFromManifest := difference(publicServiceRoutes, expectedPaths)
	manifestNotImplemented := difference(expectedPaths, publicServiceRoutes)

	if len(missingFromOpenAPI) > 0 {
		errorsOut = append(errorsOut, "OpenAPI is missing service routes: "+strings.Join(missingFromOpenAPI, ", "))
	}
	if len(notImplementedByServices) > 0 {
		errorsOut = append(errorsOut, "OpenAPI documents routes not implemented by the reference services: "+strings.Join(notImplementedByServices, ", "))
	}
	if len(missingFromManifest) > 0 {
		errorsOut = append(errorsOut, "OpenAPI method manifest is missing service routes: "+strings.Join(missingFromManifest, ", "))
	}
	if len(manifestNotImplemented) > 0 {
		errorsOut = append(errorsOut, "OpenAPI method manifest contains routes not implemented by the reference services: "+strings.Join(manifestNotImplemented, ", "))
	}

	if content != "" {
		for _, path := range expectedPaths {
			section, ok := openAPIPathSection(content, path)
			if !ok {
				continue
			}
			method := methodByPath[path]
			if !regexp.MustCompile(`(?m)^    ` + regexp.QuoteMeta(method) + `:\s*$`).MatchString(section) {
				errorsOut = append(errorsOut, "OpenAPI path "+path+" must document "+strings.ToUpper(method))
			}
			if !regexp.MustCompile(`(?m)^      responses:\s*$`).MatchString(section) {
				errorsOut = append(errorsOut, "OpenAPI path "+path+" must document responses")
			}
		}
	}

	errorsOut = append(errorsOut, validateSpecEndpoints(root, methodByPath)...)

	status := "pass"
	if len(errorsOut) > 0 {
		status = "fail"
	}
	summary := openAPISummary{
		Type:                     "iscp.openapi.validation.v2",
		GeneratedAt:              time.Now().UTC().Format(time.RFC3339Nano),
		OpenAPIFile:              "docs/api/openapi.yaml",
		RouteSources:             routeSourceNames,
		Status:                   status,
		OpenAPIPathCount:         len(openAPIPublicPaths),
		ServiceRouteCount:        len(publicServiceRoutes),
		CheckedPaths:             expectedMethods,
		MissingFromOpenAPI:       missingFromOpenAPI,
		NotImplementedByServices: notImplementedByServices,
		Errors:                   errorsOut,
	}
	if err := writeJSON(root, "dist/openapi-check.json", summary); err != nil {
		return err
	}
	if len(errorsOut) > 0 {
		return errors.New("OpenAPI validation failed; see dist/openapi-check.json")
	}
	fmt.Println("OpenAPI validation passed; see dist/openapi-check.json")
	return nil
}

var specEndpointSources = []struct {
	SpecFile string
	Prefixes []string
}{
	{SpecFile: "spec/relay.md", Prefixes: []string{"/.well-known/iscp/relay", "/v2/relay/"}},
	{SpecFile: "spec/trust-root.md", Prefixes: []string{"/.well-known/iscp/trust-root", "/v2/trust/"}},
}

var specEndpointRe = regexp.MustCompile("(?m)^- `(GET|POST) (/[^`]+)`( \\(optional\\))?")

// validateSpecEndpoints cross-checks the endpoint lists written in the protocol
// spec documents against the OpenAPI method manifest, so spec prose cannot
// drift from the machine-validated route surface again (issue #5).
func validateSpecEndpoints(root *os.Root, methodByPath map[string]string) []string {
	errorsOut := []string{}
	for _, source := range specEndpointSources {
		raw, err := root.ReadFile(filepath.FromSlash(source.SpecFile))
		if err != nil {
			errorsOut = append(errorsOut, "spec endpoint source is missing: "+source.SpecFile)
			continue
		}
		specListed := map[string]string{}
		specOptional := map[string]bool{}
		for _, match := range specEndpointRe.FindAllStringSubmatch(string(raw), -1) {
			specListed[match[2]] = strings.ToLower(match[1])
			specOptional[match[2]] = match[3] != ""
		}
		if len(specListed) == 0 {
			errorsOut = append(errorsOut, source.SpecFile+" lists no endpoints in the expected `- `METHOD /path`` form")
			continue
		}
		for path, method := range specListed {
			expected, ok := methodByPath[path]
			if !ok {
				// Optional endpoints are spec surface without a reference
				// implementation route; they are exempt from the manifest.
				if specOptional[path] {
					continue
				}
				errorsOut = append(errorsOut, source.SpecFile+" lists endpoint not present in the OpenAPI method manifest: "+strings.ToUpper(method)+" "+path)
				continue
			}
			if expected != method {
				errorsOut = append(errorsOut, source.SpecFile+" documents "+strings.ToUpper(method)+" "+path+" but the OpenAPI method manifest expects "+strings.ToUpper(expected))
			}
		}
		for path, method := range methodByPath {
			covered := false
			for _, prefix := range source.Prefixes {
				if path == prefix || strings.HasPrefix(path, prefix) {
					covered = true
					break
				}
			}
			if !covered {
				continue
			}
			if _, ok := specListed[path]; !ok {
				errorsOut = append(errorsOut, source.SpecFile+" is missing endpoint documented in the OpenAPI method manifest: "+strings.ToUpper(method)+" "+path)
			}
		}
	}
	return errorsOut
}

func validateTraceability(root *os.Root) error {
	specName := "spec/security-baseline.md"
	matrixName := "docs/security/traceability.md"
	errorsOut := []string{}

	specRaw, err := root.ReadFile(specName)
	if err != nil {
		return err
	}
	matrixRaw, err := root.ReadFile(matrixName)
	if err != nil {
		return err
	}

	requirements := extractNormativeRequirements(string(specRaw))
	rows := extractTraceabilityRows(string(matrixRaw), &errorsOut)
	requirementByNormalized := map[string]string{}
	for _, requirement := range requirements {
		normalized := normalizeRequirement(requirement)
		if previous, ok := requirementByNormalized[normalized]; ok {
			errorsOut = append(errorsOut, "duplicate normative requirement: "+previous)
			continue
		}
		requirementByNormalized[normalized] = requirement
	}

	matrixByNormalized := map[string]string{}
	ids := map[string]string{}
	duplicateIDs := []string{}
	for _, row := range rows {
		if row.ID == "" {
			errorsOut = append(errorsOut, "traceability row has empty id")
		}
		if previous, ok := ids[row.ID]; ok {
			duplicateIDs = append(duplicateIDs, row.ID)
			errorsOut = append(errorsOut, "traceability id "+row.ID+" duplicates "+previous)
		} else {
			ids[row.ID] = row.Requirement
		}
		if strings.TrimSpace(row.Evidence) == "" {
			errorsOut = append(errorsOut, row.ID+" has empty evidence")
		}
		if row.Status != "Covered" {
			errorsOut = append(errorsOut, row.ID+" status must be Covered")
		}
		matrixByNormalized[normalizeRequirement(row.Requirement)] = row.Requirement
	}

	missing := []string{}
	for normalized, requirement := range requirementByNormalized {
		if _, ok := matrixByNormalized[normalized]; !ok {
			missing = append(missing, requirement)
		}
	}
	extra := []string{}
	for normalized, requirement := range matrixByNormalized {
		if _, ok := requirementByNormalized[normalized]; !ok {
			extra = append(extra, requirement)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(duplicateIDs)
	if len(missing) > 0 {
		errorsOut = append(errorsOut, "traceability matrix is missing requirements")
	}
	if len(extra) > 0 {
		errorsOut = append(errorsOut, "traceability matrix contains requirements not in security baseline")
	}

	status := "pass"
	if len(errorsOut) > 0 {
		status = "fail"
	}
	summary := traceabilitySummary{
		Type:                "iscp.traceability.validation.v2",
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		SpecFile:            specName,
		MatrixFile:          matrixName,
		Status:              status,
		RequirementCount:    len(requirements),
		MatrixRowCount:      len(rows),
		MissingRequirements: missing,
		ExtraRequirements:   extra,
		DuplicateIDs:        duplicateIDs,
		Rows:                rows,
		Errors:              errorsOut,
	}
	if err := writeJSON(root, "dist/traceability-check.json", summary); err != nil {
		return err
	}
	if len(errorsOut) > 0 {
		return errors.New("traceability validation failed; see dist/traceability-check.json")
	}
	fmt.Println("traceability validation passed; see dist/traceability-check.json")
	return nil
}

func validateHelm(root *os.Root, rootPath string) error {
	chartDir := "deploy/helm/iscp"
	checkedFiles := []string{
		"deploy/helm/iscp/values.yaml",
		"deploy/helm/iscp/templates/relay-deployment.yaml",
		"deploy/helm/iscp/templates/trust-deployment.yaml",
		"deploy/helm/iscp/templates/relay-service.yaml",
		"deploy/helm/iscp/templates/trust-service.yaml",
	}
	errorsOut := []string{}
	for _, name := range checkedFiles {
		if _, err := root.Stat(name); err != nil {
			errorsOut = append(errorsOut, name+" is missing")
		}
	}
	values := readText(root, "deploy/helm/iscp/values.yaml", &errorsOut)
	relay := readText(root, "deploy/helm/iscp/templates/relay-deployment.yaml", &errorsOut)
	trust := readText(root, "deploy/helm/iscp/templates/trust-deployment.yaml", &errorsOut)
	for _, check := range []struct {
		name    string
		content string
		want    []string
	}{
		{"values", values, []string{"profile: local-lab", "existingSecret", "allowedOrigins", "externalURL"}},
		{"relay deployment", relay, []string{"fail \"production profile requires admin.existingSecret\"", "fail \"production profile requires relay.allowedOrigins\"", "fail \"production profile requires postgres.externalURL or postgres.existingSecret\"", "ISCP_ADMIN_TOKEN", "ISCP_DATABASE_URL", "ISCP_ALLOWED_ORIGINS", "ISCP_RELAY_BASE_URL", "ISCP_RELAY_WS_URL"}},
		{"trust deployment", trust, []string{"fail \"production profile requires admin.existingSecret\"", "fail \"production profile requires postgres.externalURL or postgres.existingSecret\"", "ISCP_ADMIN_TOKEN", "ISCP_DATABASE_URL", "ISCP_TRUST_BASE_URL"}},
	} {
		for _, want := range check.want {
			if !strings.Contains(check.content, want) {
				errorsOut = append(errorsOut, check.name+" must contain "+want)
			}
		}
	}
	status := "pass"
	if len(errorsOut) > 0 {
		status = "fail"
	}
	summary := helmSummary{
		Type:         "iscp.helm.validation.v2",
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		ChartDir:     chartDir,
		Status:       status,
		CheckedFiles: checkedFiles,
		Errors:       errorsOut,
	}
	if err := writeJSON(root, "dist/helm-check.json", summary); err != nil {
		return err
	}
	if len(errorsOut) > 0 {
		return errors.New("Helm validation failed; see dist/helm-check.json")
	}
	fmt.Println("Helm validation passed; see dist/helm-check.json")
	return nil
}

func validatePostgres(root *os.Root) error {
	dsn := strings.TrimSpace(os.Getenv("ISCP_DATABASE_URL"))
	errorsOut := []string{}
	checkedTables := []string{
		"iscp_relay.devices",
		"iscp_relay.access_tokens",
		"iscp_relay.refresh_tokens",
		"iscp_relay.pop_replay_cache",
		"iscp_relay.messages",
		"iscp_relay.delivery_receipts",
		"iscp_trust.devices",
		"iscp_trust.grants",
		"iscp_trust.revocations",
		"iscp_trust.pop_replay_cache",
		"iscp_trust.signing_keys",
	}
	replayChecks := []string{}
	queueChecks := []string{}
	if dsn == "" {
		errorsOut = append(errorsOut, "ISCP_DATABASE_URL is required")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			errorsOut = append(errorsOut, "connect failed: "+err.Error())
		} else {
			defer pool.Close()
			for _, table := range checkedTables {
				var exists bool
				if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
					errorsOut = append(errorsOut, table+" check failed: "+err.Error())
					continue
				}
				if !exists {
					errorsOut = append(errorsOut, table+" is missing")
				}
			}
			now := time.Now().UTC()
			nonce := fmt.Sprintf("postgres-check-%d", now.UnixNano())
			relayRepo := repository.NewRelayRepository(pool)
			if err := assertReplayNonce("relay", func() (bool, error) {
				return relayRepo.UseProofNonce(ctx, repository.DomainID("local"), "postgres-check-device", "relay-local", nonce, now.Add(time.Minute), now)
			}); err != nil {
				errorsOut = append(errorsOut, err.Error())
			} else {
				replayChecks = append(replayChecks, "relay proof nonce replay rejected")
			}
			trustRepo := repository.NewTrustRepository(pool)
			if err := assertReplayNonce("trust", func() (bool, error) {
				return trustRepo.UseProofNonce(ctx, repository.DomainID("local"), "postgres-check-device", "trust-local", nonce, now.Add(time.Minute), now)
			}); err != nil {
				errorsOut = append(errorsOut, err.Error())
			} else {
				replayChecks = append(replayChecks, "trust proof nonce replay rejected")
			}
			checks, err := assertRelayPersistentQueue(ctx, relayRepo, now)
			if err != nil {
				errorsOut = append(errorsOut, err.Error())
			} else {
				queueChecks = append(queueChecks, checks...)
			}
		}
	}
	status := "pass"
	if len(errorsOut) > 0 {
		status = "fail"
	}
	summary := postgresSummary{
		Type:          "iscp.postgres.validation.v2",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Status:        status,
		DSNConfigured: dsn != "",
		CheckedTables: checkedTables,
		ReplayChecks:  replayChecks,
		QueueChecks:   queueChecks,
		Errors:        errorsOut,
	}
	if err := writeJSON(root, "dist/postgres-check.json", summary); err != nil {
		return err
	}
	if len(errorsOut) > 0 {
		return errors.New("PostgreSQL validation failed; see dist/postgres-check.json")
	}
	fmt.Println("PostgreSQL validation passed; see dist/postgres-check.json")
	return nil
}

func assertReplayNonce(name string, use func() (bool, error)) error {
	first, err := use()
	if err != nil {
		return fmt.Errorf("%s replay nonce first use failed: %w", name, err)
	}
	if !first {
		return fmt.Errorf("%s replay nonce first use was rejected", name)
	}
	second, err := use()
	if err != nil {
		return fmt.Errorf("%s replay nonce second use failed: %w", name, err)
	}
	if second {
		return fmt.Errorf("%s replay nonce accepted duplicate", name)
	}
	return nil
}

func assertRelayPersistentQueue(ctx context.Context, repo repository.RelayRepository, now time.Time) ([]string, error) {
	domainID := repository.DomainID("local")
	suffix := fmt.Sprintf("%d", now.UnixNano())
	messageID := "postgres-check-msg-" + suffix
	recipientID := "postgres-check-recipient-" + suffix
	uuid, err := postgres.NewUUIDv7Like(now)
	if err != nil {
		return nil, fmt.Errorf("relay queue uuid generation failed: %w", err)
	}
	raw := []byte(fmt.Sprintf(`{"type":"iscp.secure_envelope.v2","message_id":%q}`, messageID))
	if err := repo.StoreMessage(ctx, repository.RelayMessage{
		ID:                postgres.UUIDString(uuid),
		DomainID:          domainID,
		MessageID:         messageID,
		SenderDeviceID:    "postgres-check-sender",
		RecipientDeviceID: recipientID,
		SessionID:         "postgres-check-session",
		PayloadType:       "text",
		RouteMetadata:     []byte(`{"ttl_seconds":60,"priority":1}`),
		EnvelopeRaw:       raw,
		EnvelopeCanonical: raw,
		Priority:          1,
		QueuedAt:          now,
		ExpiresAt:         now.Add(10 * time.Minute),
	}); err != nil {
		return nil, fmt.Errorf("relay queue store failed: %w", err)
	}
	first, err := repo.ClaimPendingMessagesFor(ctx, domainID, recipientID, now, time.Minute, 1)
	if err != nil {
		return nil, fmt.Errorf("relay queue first claim failed: %w", err)
	}
	if len(first) != 1 || first[0].MessageID != messageID || string(first[0].EnvelopeRaw) != string(raw) {
		return nil, fmt.Errorf("relay queue first claim returned unexpected messages")
	}
	second, err := repo.ClaimPendingMessagesFor(ctx, domainID, recipientID, now, time.Minute, 1)
	if err != nil {
		return nil, fmt.Errorf("relay queue duplicate claim failed: %w", err)
	}
	if len(second) != 0 {
		return nil, fmt.Errorf("relay queue duplicate claim returned leased message")
	}
	retryAt := now.Add(2 * time.Minute)
	retry, err := repo.ClaimPendingMessagesFor(ctx, domainID, recipientID, retryAt, time.Minute, 1)
	if err != nil {
		return nil, fmt.Errorf("relay queue retry claim failed: %w", err)
	}
	if len(retry) != 1 || retry[0].MessageID != messageID {
		return nil, fmt.Errorf("relay queue retry claim did not return leased message after expiry")
	}
	if err := repo.MarkMessageDelivered(ctx, domainID, messageID, retryAt); err != nil {
		return nil, fmt.Errorf("relay queue delivery mark failed: %w", err)
	}
	afterDelivered, err := repo.ClaimPendingMessagesFor(ctx, domainID, recipientID, retryAt.Add(time.Minute), time.Minute, 1)
	if err != nil {
		return nil, fmt.Errorf("relay queue post-delivery claim failed: %w", err)
	}
	if len(afterDelivered) != 0 {
		return nil, fmt.Errorf("relay queue returned delivered message")
	}
	return []string{
		"relay persistent queue claimed stored message",
		"relay persistent queue rejected duplicate active lease",
		"relay persistent queue retried after lease expiry",
		"relay persistent queue suppressed delivered message",
	}, nil
}

func extractNormativeRequirements(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	requirements := []string{}
	current := ""
	flush := func() {
		if current == "" {
			return
		}
		normalized := normalizeRequirement(current)
		if strings.Contains(normalized, " MUST ") || strings.Contains(normalized, " MUST NOT ") {
			requirements = append(requirements, normalized)
		}
		current = ""
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "- ") {
			flush()
			current = strings.TrimSpace(strings.TrimPrefix(line, "- "))
			continue
		}
		if current != "" && strings.HasPrefix(line, "  ") && strings.TrimSpace(line) != "" {
			current += " " + strings.TrimSpace(line)
			continue
		}
		flush()
	}
	flush()
	return requirements
}

func extractTraceabilityRows(content string, errorsOut *[]string) []traceabilityRow {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	rows := []traceabilityRow{}
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "| ISCP-SB-") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			*errorsOut = append(*errorsOut, "malformed traceability row: "+line)
			continue
		}
		rows = append(rows, traceabilityRow{
			ID:          strings.TrimSpace(parts[1]),
			Requirement: normalizeRequirement(parts[2]),
			Evidence:    strings.TrimSpace(parts[3]),
			Status:      strings.TrimSpace(parts[4]),
		})
	}
	return rows
}

func readText(root *os.Root, name string, errorsOut *[]string) string {
	raw, err := root.ReadFile(name)
	if err != nil {
		*errorsOut = append(*errorsOut, name+" cannot be read: "+err.Error())
		return ""
	}
	return string(raw)
}

func normalizeRequirement(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func generateSBOM(root *os.Root) error {
	doc := cyclonedxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cyclonedxMetadata{
			Component: cyclonedxComponent{Type: "application", Name: "iscp", Version: "0.1.0"},
		},
		Components: []cyclonedxLibrary{
			{Type: "library", Name: "golang.org/x/crypto", Version: "v0.31.0"},
			{Type: "library", Name: "github.com/jackc/pgx/v5", Version: "v5.9.2"},
			{Type: "library", Name: "github.com/gorilla/websocket", Version: "v1.5.3"},
		},
	}
	if err := writeJSON(root, "dist/sbom.cdx.json", doc); err != nil {
		return err
	}
	fmt.Println("dist/sbom.cdx.json")
	return nil
}

func writeJSON(root *os.Root, name string, value any) error {
	if err := root.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return err
	}
	file, err := root.Create(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func stringProperty(object map[string]any, name string) *string {
	if object == nil {
		return nil
	}
	value, ok := object[name].(string)
	if !ok {
		return nil
	}
	return &value
}

func objectProperty(object map[string]any, name string) map[string]any {
	if object == nil {
		return nil
	}
	value, _ := object[name].(map[string]any)
	return value
}

func stringArrayProperty(object map[string]any, name string) []string {
	if object == nil {
		return []string{}
	}
	raw, ok := object[name].([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func difference(left, right []string) []string {
	rightSet := map[string]bool{}
	for _, value := range right {
		rightSet[value] = true
	}
	out := []string{}
	for _, value := range left {
		if !rightSet[value] {
			out = append(out, value)
		}
	}
	return out
}

func extractOpenAPIPaths(content string) []string {
	re := regexp.MustCompile(`(?m)^  (/[^:]+):\s*$`)
	paths := []string{}
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		paths = append(paths, match[1])
	}
	return uniqueSorted(paths)
}

func publicRoutes(routes []string) []string {
	filtered := []string{}
	for _, route := range routes {
		if strings.HasPrefix(route, "/v2/") || strings.HasPrefix(route, "/.well-known/iscp/") || strings.HasPrefix(route, "/api/sparkclaw/iscp-control/") {
			filtered = append(filtered, route)
		}
	}
	return uniqueSorted(filtered)
}

func uniqueSorted(values []string) []string {
	set := map[string]bool{}
	for _, value := range values {
		set[value] = true
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func openAPIPathSection(content, path string) (string, bool) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	pathRe := regexp.MustCompile(`^  ` + regexp.QuoteMeta(path) + `:\s*$`)

	inSection := false
	var builder strings.Builder
	for _, line := range lines {
		if !inSection {
			if pathRe.MatchString(line) {
				inSection = true
			}
			continue
		}
		if strings.HasPrefix(line, "  /") {
			break
		}
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	if !inSection {
		return "", false
	}
	return builder.String(), true
}
