package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type discoveryFallback struct{ calls int }

func (f *discoveryFallback) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	f.calls++
	w.Header().Set("X-Original", "preserved")
	w.WriteHeader(http.StatusTeapot)
	_, _ = w.Write([]byte("original-bytes"))
}

func discoveryDocument(t *testing.T, root Anchor, manifests ...string) []byte {
	t.Helper()
	raw, err := json.Marshal(serviceDiscoveryConfig{SchemaVersion: 1, PublicAnchor: root, Descriptors: manifests})
	if err != nil {
		t.Fatal("synthetic public document could not be encoded")
	}
	return raw
}

func discoveryModule(t *testing.T, raw []byte, clock func() time.Time) *ServiceDiscovery {
	t.Helper()
	module, err := ParseServiceDiscovery(raw, clock)
	if err != nil {
		t.Fatal("synthetic signed discovery configuration rejected", err)
	}
	return module
}

func discoveryCall(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	reply := httptest.NewRecorder()
	handler.ServeHTTP(reply, request)
	return reply
}

func TestServiceDiscoveryServesExactSignedPublicManifestAndPreservesOtherHandlers(t *testing.T) {
	descriptor, root, key, now := descriptorFixture(t)
	descriptor.AdminBootstrap = adminBootstrapFixture()
	manifest, err := SignDescriptor(descriptor, root, key, now)
	if err != nil || len(manifest) > MaxManifest {
		t.Fatal("synthetic signature failed")
	}
	module := discoveryModule(t, discoveryDocument(t, root, manifest), func() time.Time { return now })
	fallback := &discoveryFallback{}
	handler := module.Wrap(fallback)
	request := httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+descriptor.ServiceID, nil)
	request.Header.Set("Origin", "https://foreign.example.invalid")
	request.Header.Set("Authorization", "DPoP synthetic-not-an-authority")
	request.Header.Set("Content-Length", "0")
	reply := discoveryCall(handler, request)
	if reply.Code != http.StatusOK || reply.Body.String() != manifest || bytes.HasSuffix(reply.Body.Bytes(), []byte("\n")) || fallback.calls != 0 {
		t.Fatal("public discovery rewrote signed bytes or delegated its namespace")
	}
	for name, expected := range map[string]string{"Content-Type": "application/jose", "Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Date": now.UTC().Format(http.TimeFormat)} {
		if reply.Header().Get(name) != expected {
			t.Fatal("public response header missing", name)
		}
	}
	if reply.Header().Get("Access-Control-Allow-Origin") != "" || reply.Header().Get("Authorization") != "" {
		t.Fatal("request headers became authority or credential output")
	}
	verified, _, err := VerifyDescriptor(reply.Body.String(), root, Floor{}, now)
	if err != nil || verified.AdminBootstrap == nil || verified.ServiceID != descriptor.ServiceID {
		t.Fatal("served descriptor cannot pass ordinary root verification")
	}
	for _, path := range []string{"/v1/device/policy", strings.TrimSuffix(ServiceDiscoveryPath, "/") + "-other"} {
		reply = discoveryCall(handler, httptest.NewRequest(http.MethodPost, path, strings.NewReader("unchanged request")))
		if reply.Code != http.StatusTeapot || reply.Body.String() != "original-bytes" || reply.Header().Get("X-Original") != "preserved" {
			t.Fatal("unrelated API behavior changed")
		}
	}
	if fallback.calls != 2 || (*ServiceDiscovery)(nil).Wrap(fallback) != fallback {
		t.Fatal("disabled or unrelated module did not preserve exact original handler")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", module, module), manifest) || strings.Contains(fmt.Sprintf("%v %#v", module, module), root.SPKI) {
		t.Fatal("module formatting disclosed configured metadata")
	}
}

func TestServiceDiscoveryRejectsMalformedRequestsUnknownAndExpiredServices(t *testing.T) {
	descriptor, root, key, now := descriptorFixture(t)
	manifest, err := SignDescriptor(descriptor, root, key, now)
	if err != nil {
		t.Fatal("synthetic signature failed")
	}
	fallback := &discoveryFallback{}
	handler := discoveryModule(t, discoveryDocument(t, root, manifest), func() time.Time { return now }).Wrap(fallback)
	path := ServiceDiscoveryPath + descriptor.ServiceID
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, path, nil), httptest.NewRequest(http.MethodHead, path, nil),
		httptest.NewRequest(http.MethodGet, path, strings.NewReader("body")),
		httptest.NewRequest(http.MethodGet, path+"?x=1", nil), httptest.NewRequest(http.MethodGet, path+"?", nil),
		httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+"%73ervice-a", nil),
		httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+"/service-a", nil),
		httptest.NewRequest(http.MethodGet, path+"/", nil), httptest.NewRequest(http.MethodGet, strings.TrimSuffix(ServiceDiscoveryPath, "/"), nil),
		httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+"unknown", nil),
		httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+strings.Repeat("a", 65), nil),
		httptest.NewRequest(http.MethodGet, "https://api.example.invalid"+path, nil),
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.URL.Fragment = "fragment" }, func(r *http.Request) { r.URL.ForceQuery = true },
		func(r *http.Request) { r.URL.RawFragment = "fragment" },
		func(r *http.Request) { r.URL.RawPath = ServiceDiscoveryPath + "%73ervice-a" },
		func(r *http.Request) { r.ContentLength = -1 }, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.Header["transfer-encoding"] = []string{"chunked"} },
		func(r *http.Request) { r.Header.Set("Trailer", "X-Any") }, func(r *http.Request) { r.Trailer = http.Header{"X-Any": []string{"x"}} },
		func(r *http.Request) { r.Header["Content-Length"] = []string{"0", "0"} },
		func(r *http.Request) { r.Header["Content-Length"] = []string{"00"} },
		func(r *http.Request) { r.RequestURI = path + "?injected" },
	} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		mutate(r)
		requests = append(requests, r)
	}
	for _, request := range requests {
		reply := discoveryCall(handler, request)
		if reply.Code != http.StatusNotFound || reply.Body.Len() != 0 || fallback.calls != 0 {
			t.Fatal("malformed/unknown request disclosed a descriptor or reached fallback")
		}
	}
	now = time.Unix(descriptor.Expires, 0).Add(-time.Nanosecond)
	if reply := discoveryCall(handler, httptest.NewRequest(http.MethodGet, path, nil)); reply.Code != http.StatusOK {
		t.Fatal("last valid second rejected")
	}
	now = time.Unix(descriptor.Expires, 0)
	if reply := discoveryCall(handler, httptest.NewRequest(http.MethodGet, path, nil)); reply.Code != http.StatusNotFound || reply.Body.Len() != 0 {
		t.Fatal("expired descriptor remained available")
	}
	// Retiring an ID in a replacement owner configuration does not fall back to
	// another service. There is no implicit hot reload or network revocation feed.
	descriptor.ServiceID = "service-b"
	descriptor.IssuedAt = now.Unix()
	descriptor.NotBefore = now.Unix()
	descriptor.Expires = now.Add(time.Hour).Unix()
	current, err := SignDescriptor(descriptor, root, key, now)
	if err != nil {
		t.Fatal("replacement signature failed")
	}
	replacement := discoveryModule(t, discoveryDocument(t, root, current), func() time.Time { return now }).Wrap(fallback)
	if reply := discoveryCall(replacement, httptest.NewRequest(http.MethodGet, path, nil)); reply.Code != http.StatusNotFound || reply.Body.Len() != 0 {
		t.Fatal("retired service used another configured manifest")
	}
}

func TestServiceDiscoveryOwnerDocumentIsClosedBoundedAndOwnsSignedInputs(t *testing.T) {
	descriptor, root, key, now := descriptorFixture(t)
	manifest, err := SignDescriptor(descriptor, root, key, now)
	if err != nil {
		t.Fatal("synthetic signature failed")
	}
	raw := discoveryDocument(t, root, manifest)
	module := discoveryModule(t, raw, func() time.Time { return now })
	for index := range raw {
		raw[index] = 'x'
	}
	if reply := discoveryCall(module.Wrap(&discoveryFallback{}), httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+descriptor.ServiceID, nil)); reply.Body.String() != manifest {
		t.Fatal("caller mutation changed owned manifest")
	}
	valid := discoveryDocument(t, root, manifest)
	padded := append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), ServiceDiscoveryConfigLimit-len(valid))...)
	discoveryModule(t, padded, func() time.Time { return now })
	if _, err := ParseServiceDiscovery(append(padded, ' '), func() time.Time { return now }); err == nil {
		t.Fatal("owner byte limit exceeded")
	}
	var manifests []string
	serviceID := func(index int) string {
		if index == 0 {
			return strings.Repeat("a", 64)
		}
		if index == 1 {
			return "b"
		}
		return fmt.Sprintf("service-%02d", index)
	}
	for index := 0; index < 32; index++ {
		d := descriptor
		d.ServiceID = serviceID(index)
		signed, e := SignDescriptor(d, root, key, now)
		if e != nil {
			t.Fatal("synthetic catalogue signature failed")
		}
		manifests = append(manifests, signed)
	}
	catalogue := discoveryModule(t, discoveryDocument(t, root, manifests...), func() time.Time { return now })
	for index, signed := range manifests {
		reply := discoveryCall(catalogue.Wrap(&discoveryFallback{}), httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+serviceID(index), nil))
		if reply.Code != http.StatusOK || reply.Body.String() != signed {
			t.Fatal("32-service boundary lost or mixed manifests")
		}
	}
	otherRoot, otherKey := anchorFixture(t, "other-offline-root", 1)
	foreign, e := SignDescriptor(descriptor, otherRoot, otherKey, now)
	if e != nil {
		t.Fatal("synthetic foreign signature failed")
	}
	second := descriptor
	second.Revision++
	duplicate, e := SignDescriptor(second, root, key, now)
	if e != nil {
		t.Fatal("synthetic duplicate signature failed")
	}
	invalid := [][]byte{nil, []byte(" "), []byte("null"), append(append([]byte(nil), valid...), []byte("{}")...),
		discoveryDocument(t, root), discoveryDocument(t, root, manifest, manifest), discoveryDocument(t, root, manifest, duplicate),
		discoveryDocument(t, root, append(manifests, manifest)...), discoveryDocument(t, root, foreign),
		discoveryDocument(t, otherRoot, manifest), discoveryDocument(t, root, strings.Repeat("x", MaxManifest+1)),
		discoveryDocument(t, root, " "+manifest), discoveryDocument(t, root, manifest+"\n")}
	for _, change := range [][2]string{{`"schemaVersion":1`, `"schemaVersion":2`}, {`"schemaVersion":1`, `"schemaVersion":null`},
		{`"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`}, {`"schemaVersion":1`, `"SchemaVersion":1`},
		{`"publicAnchor":`, `"PublicAnchor":`}, {`"lastTransition":""`, `"lastTransition":null`},
		{`"lastTransition":""`, `"lastTransition":"","unknown":0`}, {`,"lastTransition":""`, ``}} {
		changed := bytes.Replace(valid, []byte(change[0]), []byte(change[1]), 1)
		if bytes.Equal(changed, valid) {
			t.Fatal("negative fixture failed to change input")
		}
		invalid = append(invalid, changed)
	}
	invalid = append(invalid, []byte(strings.TrimSuffix(string(valid), "}")+`,"credential":"forbidden"}`),
		[]byte(`{"schemaVersion":1,"publicAnchor":null,"descriptors":[]}`),
		[]byte(strings.Replace(string(valid), `"descriptors":[`, `"descriptors":[null,`, 1)))
	var nullDescriptors map[string]json.RawMessage
	if json.Unmarshal(valid, &nullDescriptors) != nil {
		t.Fatal("synthetic null fixture decode failed")
	}
	nullDescriptors["descriptors"] = json.RawMessage("null")
	nullRaw, e := json.Marshal(nullDescriptors)
	if e != nil {
		t.Fatal("synthetic null fixture encode failed")
	}
	invalid = append(invalid, nullRaw)
	for _, input := range invalid {
		if _, e := ParseServiceDiscovery(input, func() time.Time { return now }); e == nil {
			t.Fatal("invalid owner document accepted")
		}
	}
	for _, clock := range []func() time.Time{nil, func() time.Time { return time.Time{} }, func() time.Time { return time.Unix(0, 0) }, func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, func() time.Time { return time.Unix(descriptor.Expires, 0) }} {
		if _, e := ParseServiceDiscovery(valid, clock); e == nil {
			t.Fatal("invalid/expired startup clock accepted")
		}
	}
}

func TestServiceDiscoveryRateClockAndCancellationRemainBounded(t *testing.T) {
	descriptor, root, key, now := descriptorFixture(t)
	descriptor.Expires = now.Add(30 * 24 * time.Hour).Unix()
	manifest, err := SignDescriptor(descriptor, root, key, now)
	if err != nil {
		t.Fatal("synthetic signature failed")
	}
	module := discoveryModule(t, discoveryDocument(t, root, manifest), func() time.Time { return now })
	handler := module.Wrap(&discoveryFallback{})
	path := ServiceDiscoveryPath + descriptor.ServiceID
	call := func() int { return discoveryCall(handler, httptest.NewRequest(http.MethodGet, path, nil)).Code }
	for index := 0; index < 32; index++ {
		if call() != http.StatusOK {
			t.Fatal("initial burst smaller than32")
		}
	}
	if call() != http.StatusTooManyRequests {
		t.Fatal("burst exceeded32")
	}
	now = now.Add(249 * time.Millisecond)
	if call() != http.StatusTooManyRequests {
		t.Fatal("token refilled early")
	}
	now = now.Add(time.Millisecond)
	if call() != http.StatusOK {
		t.Fatal("four-per-second token did not refill")
	}
	now = now.Add(2 * time.Second)
	for index := 0; index < 8; index++ {
		if call() != http.StatusOK {
			t.Fatal("bounded refill lost credit")
		}
	}
	if call() != http.StatusTooManyRequests {
		t.Fatal("refill exceeded four per second")
	}
	high := now
	now = now.Add(-time.Second)
	if call() != http.StatusTooManyRequests {
		t.Fatal("rollback admitted/refilled")
	}
	now = high.Add(249 * time.Millisecond)
	if call() != http.StatusTooManyRequests {
		t.Fatal("rollback moved high-water mark")
	}
	now = now.Add(time.Millisecond)
	if call() != http.StatusOK {
		t.Fatal("forward time did not recover conservatively")
	}
	now = now.Add(time.Hour)
	for index := 0; index < 32; index++ {
		if call() != http.StatusOK {
			t.Fatal("bounded maximum burst not restored")
		}
	}
	if call() != http.StatusTooManyRequests {
		t.Fatal("idle refill exceeded maximum burst")
	}
	// Cancel before dispatch: no header/body/fallback, clock access or token use.
	var clockCalls atomic.Int32
	fresh := discoveryModule(t, discoveryDocument(t, root, manifest), func() time.Time { clockCalls.Add(1); return now })
	fallback := &discoveryFallback{}
	freshHandler := fresh.Wrap(fallback)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	reply := discoveryCall(freshHandler, httptest.NewRequest(http.MethodGet, path, nil).WithContext(cancelled))
	if clockCalls.Load() != 1 || reply.Body.Len() != 0 || len(reply.Header()) != 0 || fallback.calls != 0 {
		t.Fatal("cancelled discovery produced response data or consumed work")
	}
	late, stop := context.WithCancel(context.Background())
	defer stop()
	active := false
	lateModule := discoveryModule(t, discoveryDocument(t, root, manifest), func() time.Time {
		if active {
			stop()
		}
		return now
	})
	active = true
	lateReply := discoveryCall(lateModule.Wrap(fallback), httptest.NewRequest(http.MethodGet, path, nil).WithContext(late))
	if lateReply.Body.Len() != 0 || len(lateReply.Header()) != 0 || fallback.calls != 0 {
		t.Fatal("cancelled in-flight admission published response data")
	}
	var ok, limited atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < 100; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			code := discoveryCall(freshHandler, httptest.NewRequest(http.MethodGet, path, nil)).Code
			if code == http.StatusOK {
				ok.Add(1)
			} else if code == http.StatusTooManyRequests {
				limited.Add(1)
			}
		}()
	}
	group.Wait()
	if ok.Load() != 32 || limited.Load() != 68 {
		t.Fatal("concurrent module requests exceeded shared burst")
	}
}

func TestServiceDiscoveryNormalizesWallInstantsBeforeHighWaterAdmission(t *testing.T) {
	descriptor, root, key, _ := descriptorFixture(t)
	// Time.Now includes a monotonic reading where supported. The retained and
	// returned representation must still be the same canonical UTC wall instant.
	base := time.Now()
	sample := base
	wall := base.Round(0).UTC()
	descriptor.IssuedAt = wall.Unix()
	descriptor.NotBefore = wall.Unix()
	descriptor.Expires = wall.Add(time.Hour).Unix()
	manifest, err := SignDescriptor(descriptor, root, key, base)
	if err != nil {
		t.Fatal("synthetic wall-clock descriptor signing failed")
	}
	module := discoveryModule(t, discoveryDocument(t, root, manifest), func() time.Time { return sample })
	if module.last != wall {
		t.Fatal("constructor retained a monotonic or location-dependent clock representation")
	}
	for index := 0; index < 32; index++ {
		instant, admitted := module.admit()
		if !admitted || instant != wall || module.last != wall {
			t.Fatal("admission did not normalize its clock sample before use")
		}
	}
	sample = wall.In(time.FixedZone("synthetic-offset", 9*60*60))
	if instant, admitted := module.admit(); admitted || instant != wall || module.credit != 0 || module.last != wall {
		t.Fatal("the same wall instant in another representation refilled credit")
	}
	sample = base.Add(500 * time.Millisecond)
	high := sample.Round(0).UTC()
	if instant, admitted := module.admit(); !admitted || instant != high || module.last != high || module.credit != 250*time.Millisecond {
		t.Fatal("forward monotonic-bearing sample was not normalized and bounded")
	}
	credit := module.credit
	sample = high.Add(-100 * time.Millisecond).In(time.FixedZone("synthetic-rollback", -7*60*60))
	if instant, admitted := module.admit(); admitted || instant != sample.Round(0).UTC() || module.last != high || module.credit != credit {
		t.Fatal("wall rollback moved the high-water mark or spent/refilled credit")
	}
	sample = high
	if instant, admitted := module.admit(); !admitted || instant != high || module.last != high || module.credit != 0 {
		t.Fatal("returning to the high-water instant lost existing credit or added credit")
	}
	sample = base.Add(749 * time.Millisecond)
	if _, admitted := module.admit(); admitted || module.last != sample.Round(0).UTC() || module.credit != 249*time.Millisecond {
		t.Fatal("rollback recovery refilled before the full wall-clock interval")
	}
	sample = base.Add(750 * time.Millisecond)
	if instant, admitted := module.admit(); !admitted || instant != sample.Round(0).UTC() || module.credit != 0 {
		t.Fatal("normalized wall clock did not recover after a complete refill interval")
	}
	sample = base.Add(time.Second)
	reply := discoveryCall(module.Wrap(&discoveryFallback{}), httptest.NewRequest(http.MethodGet, ServiceDiscoveryPath+descriptor.ServiceID, nil))
	if reply.Code != http.StatusOK || reply.Body.String() != manifest || reply.Header().Get("Date") != sample.Round(0).UTC().Format(http.TimeFormat) || module.last != sample.Round(0).UTC() {
		t.Fatal("served validity, Date and retained high-water instant used different clock representations")
	}
}
