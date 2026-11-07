package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/catalog"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/telemetry"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEnrollmentWireSchemasMatchRuntime(t *testing.T) {
	raw, e := contracts.Files.ReadFile("v1/enrollment-openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("OpenAPI JSON")
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatal("OpenAPI version")
	}
	compiler := jsonschema.NewCompiler()
	base := "https://contracts.example.invalid/enrollment-openapi.json"
	if e = compiler.AddResource(base, doc); e != nil {
		t.Fatal(e)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	values := map[string]any{"Enroll": Request{random(), identity.PublicJWK(&key.PublicKey), []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}}, "Cleanup": Cleanup{random(), []string{random()}}, "Mutation": map[string]string{"requestId": random()}, "Session": Session{random(), random(), random(), 1800000600000, 1800086400000, 0, random()}}
	values["OverlayOperation"] = OverlayRequest{random(), "managed-netbird/" + random(), random(), 1}
	values["OverlayCredentialReply"] = OverlayReply{Envelope: "synthetic-addressed-envelope", Consumed: false}
	values["OverlayConsumed"] = OverlayReply{Consumed: true}
	caps := []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"}
	values["CapabilityInput"] = CapabilityInput{RequestID: random(), PreviousHash: random(), Capabilities: caps}
	values["CapabilitySnapshot"] = CapabilitySnapshot{CapabilityState: CapabilityState{Version: 0, Hash: random(), Capabilities: caps}, AuthorityHash: random()}
	values["CapabilityRequest"] = CapabilityRequestView{RequestID: random(), State: "queued"}
	values["ControlPanelHint"] = ControlPanelHint{SchemaVersion: 1, UntilMs: 1800000060000}
	values["TelemetryBatch"] = telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 51, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: random(), AtMS: 1800000000000, Kind: "vpn", Code: "online", Mode: "wifi"}}}
	values["DeviceSourceLease"] = catalog.DeviceFetchLease{JobID: random(), Lease: random(), Until: 1800000060,
		NetworkModes: []string{"wifi"}, Credential: catalog.FetchCredential{URL: "https://subscription.example.invalid"},
		Validators: &catalog.DeviceFetchValidators{ETag: `"snapshot"`}}
	for name, value := range values {
		schema, e := compiler.Compile(base + "#/components/schemas/" + name)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(value)
		var object map[string]any
		json.Unmarshal(encoded, &object)
		if e = schema.Validate(object); e != nil {
			t.Fatal("runtime disagrees with wire schema", name)
		}
		object["unexpected"] = true
		if schema.Validate(object) == nil {
			t.Fatal("unknown member accepted", name)
		}
		delete(object, "unexpected")
		if name == "DeviceSourceLease" {
			original := object["validators"]
			object["validators"] = map[string]any{"unexpected": true}
			if schema.Validate(object) == nil {
				t.Fatal("unknown conditional validator accepted")
			}
			object["validators"] = original
		}
		for field := range object {
			changed := map[string]any{}
			for k, v := range object {
				if k != field {
					changed[k] = v
				}
			}
			valid := schema.Validate(changed) == nil
			if name == "DeviceSourceLease" && field == "validators" {
				if !valid {
					t.Fatal("legacy lease is no longer accepted by the shared schema")
				}
				continue
			}
			if valid {
				t.Fatal("missing required field accepted", name, field)
			}
		}
	}
	paths := doc["paths"].(map[string]any)
	expected := map[string]bool{"/v1/devices/enroll": true, "/v1/identity/devices/revoke": true, "/v1/device/session/refresh": true, "/v1/device/revoke": true, "/v1/device/policy": true, "/v1/device/control-panel": true, "/v1/device/overlay/fetch": true, "/v1/device/overlay/consume": true, "/v1/device/capabilities": true, "/v1/devices/capabilities": true, deviceFetchClaimPath: true, deviceFetchResultPath: true, deviceFetchV2ClaimPath: true, deviceFetchV2ResultPath: true, telemetryPath: true}
	if len(paths) != len(expected) {
		t.Fatal("unexpected API scope")
	}
	for path, value := range paths {
		if !expected[path] {
			t.Fatal("unexpected API endpoint")
		}
		methods := value.(map[string]any)
		if path == "/v1/device/capabilities" || path == "/v1/devices/capabilities" {
			if len(methods) != 2 {
				t.Fatal("unexpected capability API method")
			}
			security := "deviceDPoP"
			if path == "/v1/devices/capabilities" {
				security = "oidcDPoP"
			}
			for _, method := range []string{"get", "post"} {
				operation, ok := methods[method].(map[string]any)
				if !ok || operation["parameters"] == nil {
					t.Fatal("missing capability operation proof")
				}
				entries, ok := operation["security"].([]any)
				if !ok || len(entries) != 1 {
					t.Fatal("capability operation lacks authentication")
				}
				if _, ok := entries[0].(map[string]any)[security]; !ok {
					t.Fatal("wrong capability authentication audience")
				}
			}
			continue
		}
		method := "post"
		if path == "/v1/device/policy" || path == controlPanelPath || path == deviceFetchClaimPath || path == deviceFetchV2ClaimPath {
			method = "get"
		}
		if len(methods) != 1 {
			t.Fatal("unexpected API method")
		}
		operation := methods[method].(map[string]any)
		if operation["security"] == nil || operation["parameters"] == nil {
			t.Fatal("unauthenticated endpoint")
		}
	}
}
