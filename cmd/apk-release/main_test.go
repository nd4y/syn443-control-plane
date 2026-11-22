package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func TestAPKReleaseOfflineCommandChecksApprovedReceiptsAndFinalFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1700001000, 0)
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	marshal := func(v any) []byte {
		t.Helper()
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	keyPath := write("temporary-metadata-key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	t.Setenv("SYN443_APK_RELEASE_KEY_FILE", keyPath)
	spki, e := bootstrap.Public(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	cert := sum([]byte("fixture Android signing certificate"))
	zero := bootstrap.ReleaseFloor{}
	trust := trustFile{Anchor: bootstrap.Anchor{ID: "offline-fixture", SPKI: spki, Epoch: 1}, Scope: bootstrap.ReleaseScope{ServiceID: "fixture", DeviceID: identity.Hash([]byte("recipient")), Channel: "pilot", SignerSHA256: cert}, Floor: &zero,
		Installed: bootstrap.InstalledReleaseContext{VersionCode: 11, SDK: 35, ABIs: []string{"arm64-v8a"}, RequiredEngineCapabilities: []string{"tun.v1"}, Evaluator: "local-v1", Schema: "policy-v1"}}
	trustPath := write("scope.json", marshal(trust))
	unsigned := []byte("synthetic unsigned payload")
	signed := []byte("synthetic signed payload")
	apkPath := write("payload", signed)
	i := inventory{SchemaVersion: 1, Kind: "unsigned-release-input", SourceCommit: strings.Repeat("1", 40),
		NativeLibraries: map[string]string{"arm64-v8a": sum([]byte("library"))}, EngineLock: fileDigest{1, sum([]byte("e"))}, ContractLock: fileDigest{1, sum([]byte("c"))}}
	i.APK.Bytes = int64(len(unsigned))
	i.APK.SHA256 = sum(unsigned)
	i.APK.File = "app-release-unsigned.apk"
	i.APK.Package = "io.syn443.android"
	i.APK.VersionCode = 12
	i.APK.VersionName = "fixture"
	i.APK.MinSDK = 29
	i.APK.TargetSDK = 37
	inventoryBytes := marshal(i)
	inventoryPath := write("inventory.json", inventoryBytes)
	r := signingReceipt{1, "verified-apk-signing", fileDigest{int64(len(unsigned)), sum(unsigned)}, fileDigest{int64(len(signed)), sum(signed)}, cert}
	receiptBytes := marshal(r)
	receiptPath := write("receipt.json", receiptBytes)
	offer := publication{sum(inventoryBytes), sum(receiptBytes), 1, 1, 0, now.Unix(), now.Unix(), now.Add(time.Minute).Unix(), bootstrap.ReleaseCompatibility{MinimumInstalledVersion: 10, EngineCapabilities: []string{"tun.v1"}, Evaluators: []string{"local-v1"}, Schemas: []string{"policy-v1"}}}
	offerPath := write("offer.json", marshal(offer))
	issue := []string{"sign", trustPath, offerPath, inventoryPath, receiptPath, apkPath}
	var out bytes.Buffer
	if e = run(issue, now, &out); e != nil {
		t.Fatal(e)
	}
	envelope := write("manifest.jws", out.Bytes())
	verify := []string{"verify", trustPath, envelope, apkPath}
	out.Reset()
	t.Setenv("SYN443_APK_RELEASE_KEY_FILE", "")
	if e = run(verify, now, &out); e != nil {
		t.Fatal(e)
	}
	var floor bootstrap.ReleaseFloor
	if json.Unmarshal(out.Bytes(), &floor) != nil || floor.Scope != trust.Scope || floor.Revision != 1 {
		t.Fatal("verified floor")
	}
	trust.Floor = &floor
	write("scope.json", marshal(trust))
	out.Reset()
	if e = run(verify, now, &out); e != nil {
		t.Fatal(e)
	}
	rejected := func(args []string) {
		t.Helper()
		out.Reset()
		if run(args, now, &out) == nil || out.Len() != 0 {
			t.Fatal("invalid input produced output")
		}
	}
	write("payload", []byte("synthetic altered bytes!"))
	rejected(verify)
	t.Setenv("SYN443_APK_RELEASE_KEY_FILE", keyPath)
	rejected(issue)
	write("payload", signed)
	write("receipt.json", append(append([]byte{}, receiptBytes...), ' '))
	rejected(issue)
	write("receipt.json", receiptBytes)
	write("inventory.json", append(append([]byte{}, inventoryBytes...), ' '))
	rejected(issue)
	write("inventory.json", inventoryBytes)
	r.Unsigned.SHA256 = sum([]byte("different unsigned"))
	raw := marshal(r)
	write("receipt.json", raw)
	offer.ReceiptSHA256 = sum(raw)
	write("offer.json", marshal(offer))
	rejected(issue)
	trust.Installed.VersionCode = 12
	write("scope.json", marshal(trust))
	rejected(verify)
	trust.Floor = nil
	write("scope.json", marshal(trust))
	rejected(verify)
}
