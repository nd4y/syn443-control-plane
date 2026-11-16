package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/contracts"
	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
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
	values["RuntimeObservation"] = RuntimeObservation{Version: 1, Sequence: 1, Build: 74, Phase: "off", EngineKnown: true, Network: "none", SampledAtMs: 1800000000000}
	values["DeviceActivationReport"] = ActivationReport{Version: 1, PolicyRevision: 1, EnvelopeHash: random(), ActivationGeneration: 1, Outcome: "committed", ActivePolicyRevision: 1}
	values["TelemetryBatch"] = telemetry.Batch{SchemaVersion: 1, Session: random(), Build: 51, AlgorithmRevision: 1,
		Events: []telemetry.Event{{ID: random(), AtMS: 1800000000000, Kind: "vpn", Code: "online", Mode: "wifi"}}}
	values["TelemetryReceipt"] = telemetry.Receipt{SchemaVersion: 1, EventIDs: []string{random()}}
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
	expected[runtimeObservationPath] = true
	expected[activationStatusPath] = true
	expected[bootstrap.ServiceDiscoveryPath+"{serviceId}"] = true
	if len(paths) != len(expected) {
		t.Fatal("unexpected API scope")
	}
	for path, value := range paths {
		if !expected[path] {
			t.Fatal("unexpected API endpoint")
		}
		methods := value.(map[string]any)
		if path == bootstrap.ServiceDiscoveryPath+"{serviceId}" {
			checkServiceDiscoveryContract(t, methods, key)
			continue
		}
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

func checkServiceDiscoveryContract(t *testing.T, methods map[string]any, rootKey *ecdsa.PrivateKey) {
	t.Helper()
	operation, ok := methods["get"].(map[string]any)
	if !ok || len(methods) != 1 || operation["operationId"] != "discoverSignedServiceDescriptor" {
		t.Fatal("signed discovery must expose only its fixed GET operation")
	}
	security, ok := operation["security"].([]any)
	if !ok || len(security) != 0 {
		t.Fatal("signed discovery must explicitly override authentication with security[]")
	}
	if _, present := operation["requestBody"]; present {
		t.Fatal("anonymous signed discovery cannot accept a request body")
	}
	parameters, ok := operation["parameters"].([]any)
	if !ok || len(parameters) != 1 {
		t.Fatal("signed discovery requires exactly one fixed path parameter")
	}
	parameter, ok := parameters[0].(map[string]any)
	if !ok || len(parameter) != 4 || parameter["name"] != "serviceId" || parameter["in"] != "path" || parameter["required"] != true {
		t.Fatal("signed discovery parameter changed authority or location")
	}
	idSchema, ok := parameter["schema"].(map[string]any)
	if !ok || len(idSchema) != 4 || idSchema["type"] != "string" || idSchema["pattern"] != "^[A-Za-z0-9_-]{1,64}$" ||
		idSchema["minLength"] != float64(1) || idSchema["maxLength"] != float64(64) {
		t.Fatal("signed discovery service ID is no longer exactly bounded")
	}
	responses, ok := operation["responses"].(map[string]any)
	if !ok || len(responses) != 3 {
		t.Fatal("signed discovery must specify only200/404/429")
	}
	for _, status := range []string{"200", "404", "429"} {
		response, ok := responses[status].(map[string]any)
		if !ok {
			t.Fatal("missing signed discovery response", status)
		}
		if _, present := response["content"]; status != "200" && present {
			t.Fatal("signed discovery denial must have no response content", status)
		}
	}
	success := responses["200"].(map[string]any)
	content, ok := success["content"].(map[string]any)
	if !ok || len(content) != 1 {
		t.Fatal("signed discovery success must expose only application/jose")
	}
	media, ok := content["application/jose"].(map[string]any)
	if !ok || len(media) != 1 {
		t.Fatal("signed discovery JOSE media schema missing")
	}
	bodySchema, ok := media["schema"].(map[string]any)
	if !ok || len(bodySchema) != 4 || bodySchema["type"] != "string" || bodySchema["minLength"] != float64(5) ||
		bodySchema["maxLength"] != float64(bootstrap.MaxManifest) || bodySchema["pattern"] != "^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$" {
		t.Fatal("signed discovery compact envelope bounds changed")
	}
	compiler := jsonschema.NewCompiler()
	compile := func(name string, schema map[string]any) *jsonschema.Schema {
		t.Helper()
		uri := "https://contracts.example.invalid/discovery-" + name + ".json"
		if err := compiler.AddResource(uri, schema); err != nil {
			t.Fatal(err)
		}
		compiled, err := compiler.Compile(uri)
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}
	ids := compile("service-id", idSchema)
	for _, id := range []string{"a", "A_09-z", strings.Repeat("a", 64)} {
		if ids.Validate(id) != nil {
			t.Fatal("valid runtime service ID rejected by contract")
		}
	}
	for _, id := range []string{"", strings.Repeat("a", 65), "a/b", "a%2Fb", "a.b", "a\n", "é"} {
		if ids.Validate(id) == nil {
			t.Fatal("unsafe service ID accepted by contract")
		}
	}
	envelopes := compile("manifest", bodySchema)
	// Schema-only compact syntax at the byte limit, not a trusted signature.
	maximum := "e30." + strings.Repeat("A", 6052) + "." + strings.Repeat("A", 87)
	if len(maximum) != bootstrap.MaxManifest || envelopes.Validate(maximum) != nil {
		t.Fatal("exact6144-byte compact contract boundary rejected")
	}
	for _, invalid := range []any{"", maximum + "A", "one.two", "one.two.three\n", "one=.two.three", nil} {
		if envelopes.Validate(invalid) == nil {
			t.Fatal("invalid compact envelope accepted by contract")
		}
	}
	if rootKey == nil {
		t.Fatal("synthetic root unavailable")
	}
	rootSPKI, err := bootstrap.Public(&rootKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	online, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicationSPKI, err := bootstrap.Public(&online.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := bootstrap.Anchor{ID: "wire-discovery-root", SPKI: rootSPKI, Epoch: 1}
	now := time.Unix(1800000000, 0)
	descriptor := bootstrap.Descriptor{SchemaVersion: 1, Audience: "syn443-client-bootstrap", RootEpoch: 1, Revision: 1,
		ServiceID: "wire-service", Issuer: "https://id.example.invalid/realms/device", ClientID: "syn443-android",
		APIOrigin: "https://api.example.invalid", Roots: map[string]string{"online": publicationSPKI},
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	manifest, err := bootstrap.SignDescriptor(descriptor, root, rootKey, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"schemaVersion": 1, "publicAnchor": root, "descriptors": []string{manifest}})
	if err != nil {
		t.Fatal(err)
	}
	module, err := bootstrap.ParseServiceDiscovery(raw, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler := module.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	call := func(id string) *httptest.ResponseRecorder {
		reply := httptest.NewRecorder()
		handler.ServeHTTP(reply, httptest.NewRequest(http.MethodGet, bootstrap.ServiceDiscoveryPath+id, nil))
		return reply
	}
	reply := call(descriptor.ServiceID)
	if reply.Code != http.StatusOK || reply.Header().Get("Content-Type") != "application/jose" || reply.Body.String() != manifest ||
		len(reply.Body.Bytes()) > bootstrap.MaxManifest || envelopes.Validate(reply.Body.String()) != nil {
		t.Fatal("actual signed discovery success disagrees with contract")
	}
	if missing := call("unknown-service"); missing.Code != http.StatusNotFound || missing.Body.Len() != 0 {
		t.Fatal("actual404 discovery response is not empty as contracted")
	}
	for index := 0; index < 30; index++ {
		if call(descriptor.ServiceID).Code != http.StatusOK {
			t.Fatal("runtime burst changed before contracted429 boundary")
		}
	}
	if limited := call(descriptor.ServiceID); limited.Code != http.StatusTooManyRequests || limited.Body.Len() != 0 {
		t.Fatal("actual429 discovery response is not empty as contracted")
	}
}
