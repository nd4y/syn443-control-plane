package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func fingerprintGrant(now time.Time, subject string) enrollment.Grant {
	engine := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	sum := sha256.Sum256(engine)
	return enrollment.Grant{
		Issuer: "https://identity.example.invalid/realms/synthetic-private-issuer", Subject: subject,
		DeviceLimit: 2, Until: now.Add(time.Hour).Unix(),
		Template: policy.Payload{
			SchemaVersion: 1, Operation: "configure", Revision: 1, Audience: "syn443-device",
			RequiredCapabilities: []string{"engine-config.v1", "tun.lease.v1", "policy.keybound.v2"},
			AlgorithmRevision:    "m1-local-v1", EngineConfigB64: base64.RawURLEncoding.EncodeToString(engine),
			ContentHash: hex.EncodeToString(sum[:]), Activation: policy.Gate{TimeoutSeconds: 30,
				Checks: []policy.Check{{ID: "internet", Type: "https_204", Target: "https://health.example.org/generate_204", Required: true}}},
		},
	}
}

func fingerprintInput(t *testing.T, grants ...enrollment.Grant) []byte {
	t.Helper()
	raw, err := json.Marshal(grants)
	if err != nil {
		t.Fatal("synthetic grant serialization failed")
	}
	return raw
}

func requireFingerprintInvalid(t *testing.T, input []byte, now time.Time) {
	t.Helper()
	var output bytes.Buffer
	err := fingerprintGrants(bytes.NewReader(input), &output, func() time.Time { return now })
	if err != identity.ErrInvalid || err.Error() != "identity_invalid" || output.Len() != 0 {
		t.Fatal("invalid grant input must produce only a finite error and no metadata")
	}
}

func TestGrantFingerprintMatchesNativeOwnerHashAndExactClosedMetadata(t *testing.T) {
	now := time.Unix(1800000000, 0)
	first := fingerprintGrant(now, "synthetic-private-subject-a")
	first.OverlayGroups = map[string][]string{"synthetic-overlay": {"synthetic-group"}}
	second := fingerprintGrant(now, "synthetic-private-subject-b")
	second.DeviceLimit = 16
	grants := []enrollment.Grant{first, second}
	var output bytes.Buffer
	if fingerprintGrants(bytes.NewReader(fingerprintInput(t, grants...)), &output, func() time.Time { return now }) != nil {
		t.Fatal("valid native grants rejected")
	}
	var document grantFingerprintDocument
	if identity.DecodeOperatorDocument(output.Bytes(), &document) != nil || document.Version != 1 || len(document.Grants) != len(grants) || output.Len() > grantFingerprintOutputLimit {
		t.Fatal("wrong closed metadata document")
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(output.Bytes(), &outer) != nil || len(outer) != 2 || outer["version"] == nil || outer["grants"] == nil {
		t.Fatal("unexpected fingerprint root fields")
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(outer["grants"], &rows) != nil {
		t.Fatal("invalid fingerprint rows")
	}
	for index, grant := range grants {
		row := document.Grants[index]
		if row.Owner != enrollment.Owner(grant.Issuer, grant.Subject) || row.GrantHash != grant.Hash() ||
			!row.Enabled || row.DeviceLimit != grant.DeviceLimit || row.ValidUntil != grant.Until {
			t.Fatal("metadata differs from the actual native owner, hash or grant")
		}
		if len(rows[index]) != 5 {
			t.Fatal("unexpected fingerprint row field")
		}
		for _, name := range []string{"owner", "enabled", "deviceLimit", "validUntil", "grantHash"} {
			if rows[index][name] == nil {
				t.Fatal("missing fingerprint row field")
			}
		}
	}
	for _, private := range []string{first.Issuer, first.Subject, second.Subject, first.Template.EngineConfigB64,
		"template", "issuer", "subject", "synthetic-overlay", "synthetic-group"} {
		if bytes.Contains(output.Bytes(), []byte(private)) {
			t.Fatal("private grant content reached the metadata output")
		}
	}
}

func TestGrantFingerprintRejectsUnknownDuplicateExpiredAndInvalidNativeTemplates(t *testing.T) {
	now := time.Unix(1800000000, 0)
	original := fingerprintInput(t, fingerprintGrant(now, "synthetic-private-subject"))
	for _, input := range []string{
		strings.Replace(string(original), `"subject":`, `"unknown":true,"subject":`, 1),
		strings.Replace(string(original), `"subject":`, `"Subject":`, 1),
		strings.Replace(string(original), `"subject":`, `"subject":"duplicate-private","subject":`, 1),
		strings.Replace(string(original), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1),
		strings.Replace(string(original), `"schemaVersion":1`, `"schemaVersion":1,"hidden":true`, 1),
		strings.Replace(string(original), `"template":{`, `"Template":{`, 1),
	} {
		if input == string(original) {
			t.Fatal("negative fixture must alter its intended native field")
		}
		requireFingerprintInvalid(t, []byte(input), now)
	}
	var nullTemplate []map[string]json.RawMessage
	if json.Unmarshal(original, &nullTemplate) != nil || len(nullTemplate) != 1 {
		t.Fatal("synthetic native document shape changed")
	}
	nullTemplate[0]["template"] = json.RawMessage("null")
	nullInput, err := json.Marshal(nullTemplate)
	if err != nil {
		t.Fatal("synthetic null-template serialization failed")
	}
	requireFingerprintInvalid(t, nullInput, now)
	for _, change := range []func(*enrollment.Grant){
		func(g *enrollment.Grant) { g.Until = now.Unix() },
		func(g *enrollment.Grant) { g.Until = now.Unix() - 1 },
		func(g *enrollment.Grant) { g.Until = now.Unix() + 604801 },
		func(g *enrollment.Grant) { g.DeviceLimit = 0 },
		func(g *enrollment.Grant) { g.DeviceLimit = 17 },
		func(g *enrollment.Grant) { g.Template.Operation = "release" },
		func(g *enrollment.Grant) { g.Template = policy.Payload{} },
		func(g *enrollment.Grant) {
			g.Template.KeyThumbprint = identity.Hash([]byte("synthetic-private-key-binding"))
		},
		func(g *enrollment.Grant) { g.Template.EngineConfigB64 = "invalid=" },
		func(g *enrollment.Grant) { g.Template.ContentHash = strings.Repeat("0", 64) },
		func(g *enrollment.Grant) {
			g.Template.RequiredCapabilities = append(g.Template.RequiredCapabilities, policy.RouteAdaptiveTCP)
		},
	} {
		grant := fingerprintGrant(now, "synthetic-private-subject")
		change(&grant)
		requireFingerprintInvalid(t, fingerprintInput(t, grant), now)
	}
}

type fingerprintReadCounter struct {
	reader io.Reader
	read   int
	eof    bool
}

func (r *fingerprintReadCounter) Read(target []byte) (int, error) {
	n, err := r.reader.Read(target)
	r.read += n
	r.eof = err == io.EOF
	return n, err
}

func TestGrantFingerprintBoundsFullStdinDocumentCountTrailingBytesAndPostReadClock(t *testing.T) {
	now := time.Unix(1800000000, 0)
	valid := fingerprintInput(t, fingerprintGrant(now, "synthetic-private-subject"))
	exact := append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), grantFingerprintInputLimit-len(valid))...)
	var output bytes.Buffer
	if fingerprintGrants(bytes.NewReader(exact), &output, func() time.Time { return now }) != nil {
		t.Fatal("exact 512 KiB stdin boundary rejected")
	}
	reader := &fingerprintReadCounter{reader: bytes.NewReader(append(exact, bytes.Repeat([]byte(" "), 4096)...))}
	output.Reset()
	if fingerprintGrants(reader, &output, func() time.Time { return now }) != identity.ErrInvalid || output.Len() != 0 || reader.read != grantFingerprintInputLimit+1 {
		t.Fatal("oversize stdin must stop at the bounded extra byte without output")
	}
	for _, raw := range [][]byte{nil, []byte(" "), []byte("[]"), []byte("null"), []byte("{}"),
		append(append([]byte(nil), valid...), valid...), append(append([]byte(nil), valid...), []byte(" {}")...),
		append(append([]byte(nil), valid...), byte(0xff)), []byte("[{")} {
		requireFingerprintInvalid(t, raw, now)
	}
	grants := make([]enrollment.Grant, 17)
	for index := range grants {
		grants[index] = fingerprintGrant(now, fmt.Sprintf("synthetic-subject-%d", index))
	}
	output.Reset()
	if fingerprintGrants(bytes.NewReader(fingerprintInput(t, grants[:16]...)), &output, func() time.Time { return now }) != nil || output.Len() > grantFingerprintOutputLimit {
		t.Fatal("sixteen bounded grants rejected")
	}
	requireFingerprintInvalid(t, fingerprintInput(t, grants...), now)
	reader = &fingerprintReadCounter{reader: bytes.NewReader(valid)}
	clockCalls := 0
	output.Reset()
	err := fingerprintGrants(reader, &output, func() time.Time {
		clockCalls++
		if !reader.eof {
			t.Fatal("clock observed before the complete stdin snapshot")
		}
		return now.Add(2 * time.Hour)
	})
	if err != identity.ErrInvalid || output.Len() != 0 || clockCalls != 1 {
		t.Fatal("grant expiring while stdin is read must fail against the post-read live clock")
	}
}

func TestGrantFingerprintRejectsDuplicateOwnersEvenWhenTheirGrantHashesDiffer(t *testing.T) {
	now := time.Unix(1800000000, 0)
	first := fingerprintGrant(now, "synthetic-private-subject")
	requireFingerprintInvalid(t, fingerprintInput(t, first, first), now)
	second := first
	second.DeviceLimit++
	if first.Hash() == second.Hash() || enrollment.Owner(first.Issuer, first.Subject) != enrollment.Owner(second.Issuer, second.Subject) {
		t.Fatal("duplicate-owner fixture does not distinguish owner and grant hash")
	}
	requireFingerprintInvalid(t, fingerprintInput(t, first, second), now)
	second.Issuer = "https://other.example.invalid/realms/synthetic"
	var output bytes.Buffer
	if fingerprintGrants(bytes.NewReader(fingerprintInput(t, first, second)), &output, func() time.Time { return now }) != nil {
		t.Fatal("distinct native owners with the same subject must remain independent")
	}
}

type fingerprintWriter struct {
	bytes.Buffer
	calls int
	short bool
	err   error
}

func (w *fingerprintWriter) Write(raw []byte) (int, error) {
	w.calls++
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return w.Buffer.Write(raw[:len(raw)-1])
	}
	return w.Buffer.Write(raw)
}

type fingerprintReaderError struct{}

func (fingerprintReaderError) Read([]byte) (int, error) {
	return 0, errors.New("synthetic-private-read-error")
}

func TestGrantFingerprintValidatesEveryGrantBeforeOneWriteAndKeepsErrorsFinite(t *testing.T) {
	now := time.Unix(1800000000, 0)
	valid := fingerprintGrant(now, "synthetic-private-subject")
	invalid := fingerprintGrant(now, "synthetic-private-subject-last")
	invalid.DeviceLimit = 0
	writer := &fingerprintWriter{}
	clock := func() time.Time { return now }
	if fingerprintGrants(nil, writer, clock) != identity.ErrInvalid ||
		fingerprintGrants(bytes.NewReader(nil), nil, clock) != identity.ErrInvalid ||
		fingerprintGrants(bytes.NewReader(nil), writer, nil) != identity.ErrInvalid || writer.calls != 0 {
		t.Fatal("missing command dependencies must fail before reading or writing")
	}
	if fingerprintGrants(bytes.NewReader(fingerprintInput(t, valid, invalid)), writer, func() time.Time { return now }) != identity.ErrInvalid || writer.calls != 0 || writer.Len() != 0 {
		t.Fatal("a later invalid grant must not emit an earlier fingerprint prefix")
	}
	if fingerprintGrants(fingerprintReaderError{}, writer, func() time.Time { return now }) != identity.ErrInvalid || writer.calls != 0 {
		t.Fatal("stdin read error escaped or emitted metadata")
	}
	for _, sink := range []*fingerprintWriter{{short: true}, {err: errors.New("synthetic-private-write-error")}, {}} {
		err := fingerprintGrants(bytes.NewReader(fingerprintInput(t, valid)), sink, func() time.Time { return now })
		if sink.calls != 1 || sink.Len() > grantFingerprintOutputLimit || bytes.Contains(sink.Bytes(), []byte("synthetic-private")) {
			t.Fatal("validated output must be one bounded metadata-only write")
		}
		if sink.short || sink.err != nil {
			if err != identity.ErrInvalid || err.Error() != "identity_invalid" {
				t.Fatal("stdout failure must return only the finite generic error")
			}
		} else if err != nil {
			t.Fatal("complete metadata write failed")
		}
	}
}

func TestGrantFingerprintActualEarlyCommandNeedsNoConfigEnvironmentOrDatabase(t *testing.T) {
	// No parallel tests: the actual CLI uses process-owned Args/Stdin/Stdout.
	args, stdin, stdout := os.Args, os.Stdin, os.Stdout
	t.Cleanup(func() { os.Args, os.Stdin, os.Stdout = args, stdin, stdout })
	t.Setenv("SYN443_ENROLLMENT_CONFIG", filepath.Join(t.TempDir(), "must-not-read-config.json"))
	t.Setenv("SYN443_ENROLLMENT_GRANTS", filepath.Join(t.TempDir(), "must-not-read-grants.json"))
	input, err := os.CreateTemp(t.TempDir(), "synthetic-stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.CreateTemp(t.TempDir(), "synthetic-stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	now := time.Now()
	grant := fingerprintGrant(now, "synthetic-private-command-subject")
	if _, err = input.Write(fingerprintInput(t, grant)); err != nil {
		t.Fatal(err)
	}
	if _, err = input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"enrollment-admin", "fingerprint-grants"}
	os.Stdin, os.Stdout = input, output
	if run() != nil {
		t.Fatal("read-only fingerprint command attempted ordinary config or database initialization")
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(output, grantFingerprintOutputLimit+1))
	var document grantFingerprintDocument
	if err != nil || identity.DecodeOperatorDocument(raw, &document) != nil || len(document.Grants) != 1 || document.Grants[0].GrantHash != grant.Hash() {
		t.Fatal("actual early command did not return the native fingerprint")
	}
	if err = output.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err = output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"enrollment-admin", "fingerprint-grants", "--config"}
	if run() != identity.ErrInvalid {
		t.Fatal("fingerprint command must not accept flags or fall through")
	}
	if info, err := output.Stat(); err != nil || info.Size() != 0 {
		t.Fatal("invalid command arguments emitted metadata")
	}
}
