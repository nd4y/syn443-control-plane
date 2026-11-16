package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func adminBootstrapFixture() *AdminBootstrap {
	return &AdminBootstrap{Issuer: "https://admin-id.example.invalid/realms/control", ClientID: AdminClientID,
		Audience: AdminAudience, APIOrigin: "https://admin-api.example.invalid", AssuranceACR: AdminAssuranceACR}
}

func TestSignedAdminBootstrapKeepsDeviceProjectionAndRequiresRevisionAdvance(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	d.ControlPanelOrigin = "https://console.example.invalid"
	legacyJSON, _ := json.Marshal(d)
	legacyCanonical, _ := policy.Canonical(legacyJSON)
	if bytes.Contains(legacyJSON, []byte("adminBootstrap")) {
		t.Fatal("absent optional metadata changed legacy bytes")
	}
	legacy, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	old, floor, e := VerifyDescriptor(legacy, root, Floor{}, now)
	if e != nil || old.AdminBootstrap != nil {
		t.Fatal("legacy descriptor invented administrative authority", e)
	}
	d.AdminBootstrap = adminBootstrapFixture()
	changed, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e := VerifyDescriptor(changed, root, floor, now); !errors.Is(e, ErrRollback) {
		t.Fatal("metadata changed under an already accepted revision", e)
	}
	d.Revision++
	changed, e = SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	got, next, e := VerifyDescriptor(changed, root, floor, now)
	if e != nil || got.AdminBootstrap == nil || *got.AdminBootstrap != *d.AdminBootstrap || next.Revision != 2 {
		t.Fatal("separate signed administrative metadata lost its authority", e)
	}
	if got.AdminBootstrap.Issuer == got.Issuer || got.AdminBootstrap.APIOrigin == got.APIOrigin || got.AdminBootstrap.APIOrigin == got.ControlPanelOrigin {
		t.Fatal("administrative metadata borrowed the device issuer or browser origin")
	}
	// Excluding only the new metadata and its required descriptor revision,
	// ordinary device bootstrap serialization remains byte-for-byte unchanged.
	got.AdminBootstrap, got.Revision = nil, old.Revision
	projectedJSON, _ := json.Marshal(got)
	projectedCanonical, _ := policy.Canonical(projectedJSON)
	if !bytes.Equal(projectedCanonical, legacyCanonical) {
		t.Fatal("administrative metadata changed the ordinary device projection")
	}
	if _, _, e := VerifyDescriptor(legacy, root, next, now); !errors.Is(e, ErrRollback) {
		t.Fatal("legacy absence bypassed the accepted service floor", e)
	}
	if AdminScope != "openid syn443.control" || AdminCallback != "syn443://admin/oauth/callback" {
		t.Fatal("fixed administrative OAuth protocol changed")
	}
}

func TestSignedAdminBootstrapTamperRemovalAndRevisionFences(t *testing.T) {
	d, root, key, now := descriptorFixture(t)
	d.AdminBootstrap = adminBootstrapFixture()
	raw, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	_, floor, e := VerifyDescriptor(raw, root, Floor{}, now)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(raw, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	changedPayload := bytes.Replace(payload, []byte("admin-api.example.invalid"), []byte("foreign-api.example.invalid"), 1)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(changedPayload) + "." + parts[2]
	if _, _, e := VerifyDescriptor(tampered, root, floor, now); e == nil {
		t.Fatal("unsigned administrative origin replacement gained trust")
	}
	d.AdminBootstrap = nil
	removed, e := SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e := VerifyDescriptor(removed, root, floor, now); !errors.Is(e, ErrRollback) {
		t.Fatal("same-revision metadata removal bypassed the service floor", e)
	}
	d.Revision++
	removed, e = SignDescriptor(d, root, key, now)
	if e != nil {
		t.Fatal(e)
	}
	got, next, e := VerifyDescriptor(removed, root, floor, now)
	if e != nil || got.AdminBootstrap != nil || next.Revision != d.Revision {
		t.Fatal("signed higher-revision metadata removal was not exact absence", e)
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v %#v", adminBootstrapFixture(), adminBootstrapFixture())), []byte("admin-api.example.invalid")) {
		t.Fatal("administrative metadata leaked through diagnostic formatting")
	}
}

type adminBootstrapVectors struct {
	Version              int    `json:"version"`
	Now                  int64  `json:"now"`
	LegacyDescriptorJSON string `json:"legacyDescriptorJson"`
	Valid                []struct {
		Name           string `json:"name"`
		DescriptorJSON string `json:"descriptorJson"`
	} `json:"valid"`
	Invalid []struct {
		Name               string `json:"name"`
		AdminBootstrapJSON string `json:"adminBootstrapJson"`
	} `json:"invalid"`
}

func readAdminBootstrapVectors(t *testing.T) adminBootstrapVectors {
	t.Helper()
	raw, e := contracts.Files.ReadFile("v1/bootstrap-admin-vectors.json")
	var vectors adminBootstrapVectors
	if e != nil || identity.Decode(raw, &vectors, true) != nil || vectors.Version != 1 || len(vectors.Valid) != 4 || len(vectors.Invalid) != 54 {
		t.Fatal("shared administrative bootstrap vectors changed unexpectedly", e)
	}
	return vectors
}

func TestSharedAdminBootstrapVectorsRequireClosedObjectAndKeepLegacySignedBytes(t *testing.T) {
	vectors := readAdminBootstrapVectors(t)
	now := time.Unix(vectors.Now, 0)
	root, key := anchorFixture(t, "shared-admin-metadata-root", 1)
	names := map[string]bool{}
	for _, v := range vectors.Valid {
		if names[v.Name] {
			t.Fatal("duplicate shared vector name")
		}
		names[v.Name] = true
		var d Descriptor
		if e := identity.Decode([]byte(v.DescriptorJSON), &d, true); e != nil {
			t.Fatal("valid shared descriptor syntax rejected", v.Name, e)
		}
		encoded, e := json.Marshal(d)
		canonical, canonicalError := policy.Canonical(encoded)
		if e != nil || canonicalError != nil || string(canonical) != v.DescriptorJSON {
			t.Fatal("shared canonical serialization changed", v.Name)
		}
		if v.Name == "legacy-absent" && (d.AdminBootstrap != nil || v.DescriptorJSON != vectors.LegacyDescriptorJSON) {
			t.Fatal("legacy shared absence was not byte-compatible")
		}
		certificate, e := SignDescriptor(d, root, key, now)
		if e != nil {
			t.Fatal("valid shared metadata could not be signed", v.Name, e)
		}
		if _, _, e := VerifyDescriptor(certificate, root, Floor{}, now); e != nil {
			t.Fatal("valid signed shared metadata rejected", v.Name, e)
		}
	}
	header, _ := policy.Canonical([]byte(`{"alg":"ES256","kid":"shared-admin-metadata-root","typ":"syn443-bootstrap+jws"}`))
	for _, v := range vectors.Invalid {
		if names[v.Name] {
			t.Fatal("duplicate shared vector name")
		}
		names[v.Name] = true
		// Preserve duplicate/case/null syntax instead of collapsing it through a
		// map. Even a valid offline signature cannot bless this unsupported wire.
		payload := []byte(`{"adminBootstrap":` + v.AdminBootstrapJSON + `,` + vectors.LegacyDescriptorJSON[1:])
		certificate := rawEnvelope(t, key, header, payload)
		if _, _, e := VerifyDescriptor(certificate, root, Floor{}, now); e == nil {
			t.Fatal("unsupported signed administrative metadata accepted", v.Name)
		}
	}
	legacyWire, e := contracts.Files.ReadFile("v1/bootstrap-wire-vectors.json")
	var old struct {
		Manifest wireParts `json:"manifest"`
	}
	if e != nil || json.Unmarshal(legacyWire, &old) != nil {
		t.Fatal("existing signed certificate fixture missing", e)
	}
	legacyPayload, e := base64.RawURLEncoding.DecodeString(old.Manifest.Payload)
	if e != nil || string(legacyPayload) != vectors.LegacyDescriptorJSON {
		t.Fatal("new vectors rewrote the old signed payload bytes", e)
	}
}

func TestAdminBootstrapSchemaClosesFieldsAndPreservesManifestBudgets(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/bootstrap.schema.json")
	var schemaJSON any
	if e != nil || json.Unmarshal(raw, &schemaJSON) != nil {
		t.Fatal("bootstrap schema missing", e)
	}
	compiler := jsonschema.NewCompiler()
	const base = "https://schemas.example.invalid/syn443/bootstrap-v1"
	if e := compiler.AddResource(base, schemaJSON); e != nil {
		t.Fatal(e)
	}
	schema, e := compiler.Compile(base + "#/$defs/AdminBootstrap")
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(adminBootstrapFixture())
	var object map[string]any
	_ = json.Unmarshal(encoded, &object)
	if e := schema.Validate(object); e != nil {
		t.Fatal("valid administrative schema rejected", e)
	}
	if schema.Validate(nil) == nil || schema.Validate(map[string]any{}) == nil {
		t.Fatal("null/empty admin object admitted")
	}
	for key := range object {
		bad := map[string]any{}
		for name, value := range object {
			if name != key {
				bad[name] = value
			}
		}
		if schema.Validate(bad) == nil {
			t.Fatal("missing administrative authority field admitted", key)
		}
	}
	object["callback"] = AdminCallback
	if schema.Validate(object) == nil {
		t.Fatal("configurable protocol callback admitted")
	}
	d, root, key, now := descriptorFixture(t)
	d.AdminBootstrap = adminBootstrapFixture()
	d.AdminBootstrap.Issuer = "https://admin-id.example.invalid/" + strings.Repeat("x", 2049)
	if _, e := SignDescriptor(d, root, key, now); e == nil {
		t.Fatal("oversized administrative issuer signed")
	}
	d.AdminBootstrap = adminBootstrapFixture()
	prefix := "https://admin-id.example.invalid/"
	d.AdminBootstrap.Issuer = prefix + strings.Repeat("x", 2048-len(prefix))
	d.AdminBootstrap.APIOrigin = "https://" + strings.Repeat("a", 2040)
	if d.AdminBootstrap.validate() != nil {
		t.Fatal("individual URL bounds fixture invalid")
	}
	if _, e := SignDescriptor(d, root, key, now); e == nil {
		t.Fatal("administrative metadata widened the aggregate signed payload budget")
	}
	if MaxManifest != 6144 {
		t.Fatal("administrative metadata widened the existing manifest budget")
	}
}
