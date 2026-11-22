// Command apk-release issues and checks addressed APK metadata offline.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nd4y/syn443-control-plane/internal/bootstrap"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/identity"
	"io"
	"os"
	"time"
)

var rejected = errors.New("APK release input rejected")

type trustFile struct {
	Installed bootstrap.InstalledReleaseContext `json:"installed"`
	Anchor    bootstrap.Anchor                  `json:"anchor"`
	Scope     bootstrap.ReleaseScope            `json:"scope"`
	Floor     *bootstrap.ReleaseFloor           `json:"floor"`
}
type publication struct {
	InventorySHA256 string                         `json:"inventorySha256"`
	ReceiptSHA256   string                         `json:"receiptSha256"`
	SecurityEpoch   int64                          `json:"securityEpoch"`
	Revision        int64                          `json:"revision"`
	RevocationFloor int64                          `json:"revocationFloor"`
	IssuedAt        int64                          `json:"issuedAt"`
	NotBefore       int64                          `json:"notBefore"`
	Expires         int64                          `json:"expires"`
	Compatibility   bootstrap.ReleaseCompatibility `json:"compatibility"`
}
type fileDigest struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type inventory struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	SourceCommit  string `json:"sourceCommit"`
	APK           struct {
		Bytes       int64  `json:"bytes"`
		SHA256      string `json:"sha256"`
		File        string `json:"file"`
		Package     string `json:"package"`
		VersionCode int64  `json:"versionCode"`
		VersionName string `json:"versionName"`
		MinSDK      int    `json:"minSdk"`
		TargetSDK   int    `json:"targetSdk"`
	} `json:"apk"`
	NativeLibraries map[string]string `json:"nativeLibraries"`
	EngineLock      fileDigest        `json:"engineLock"`
	ContractLock    fileDigest        `json:"contractLock"`
}
type signingReceipt struct {
	SchemaVersion int        `json:"schemaVersion"`
	Kind          string     `json:"kind"`
	Unsigned      fileDigest `json:"unsigned"`
	Signed        fileDigest `json:"signed"`
	SignerSHA256  string     `json:"signerCertificateSha256"`
}

func sum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func manifest(t trustFile, p publication, inventoryBytes, receiptBytes []byte) (bootstrap.ReleaseManifest, error) {
	var inv inventory
	var receipt signingReceipt
	if sum(inventoryBytes) != p.InventorySHA256 || sum(receiptBytes) != p.ReceiptSHA256 ||
		identity.Decode(inventoryBytes, &inv, true) != nil || identity.Decode(receiptBytes, &receipt, true) != nil ||
		inv.SchemaVersion != 1 || inv.Kind != "unsigned-release-input" || inv.APK.File != "app-release-unsigned.apk" ||
		receipt.SchemaVersion != 1 || receipt.Kind != "verified-apk-signing" ||
		receipt.Unsigned != (fileDigest{inv.APK.Bytes, inv.APK.SHA256}) || inv.APK.Bytes < 1 || inv.APK.Bytes > bootstrap.MaxReleaseAPKBytes ||
		receipt.SignerSHA256 != t.Scope.SignerSHA256 || receipt.Signed.SHA256 == receipt.Unsigned.SHA256 ||
		inv.EngineLock.Bytes < 1 || inv.ContractLock.Bytes < 1 {
		return bootstrap.ReleaseManifest{}, rejected
	}
	return bootstrap.ReleaseManifest{
		SchemaVersion: 1, Audience: "syn443-device-release", Scope: t.Scope, RootEpoch: t.Anchor.Epoch,
		SecurityEpoch: p.SecurityEpoch, Revision: p.Revision, RevocationFloor: p.RevocationFloor,
		IssuedAt: p.IssuedAt, NotBefore: p.NotBefore, Expires: p.Expires, Compatibility: p.Compatibility,
		APK: bootstrap.ReleaseArtifact{Package: inv.APK.Package, VersionCode: inv.APK.VersionCode, MinSDK: inv.APK.MinSDK, TargetSDK: inv.APK.TargetSDK,
			NativeLibraries: inv.NativeLibraries, SHA256: receipt.Signed.SHA256, Bytes: receipt.Signed.Bytes, SourceCommit: inv.SourceCommit,
			EngineLockSHA256: inv.EngineLock.SHA256, ContractLockSHA256: inv.ContractLock.SHA256},
	}, nil
}

func openBounded(path string, max int64) (*os.File, error) {
	prior, e := os.Lstat(path)
	if e != nil || !prior.Mode().IsRegular() || prior.Size() < 1 || prior.Size() > max {
		return nil, rejected
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, rejected
	}
	info, e := f.Stat()
	if e != nil || !os.SameFile(prior, info) || !info.Mode().IsRegular() || info.Size() != prior.Size() {
		f.Close()
		return nil, rejected
	}
	return f, nil
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := openBounded(path, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(b) == 0 || int64(len(b)) > max {
		return nil, rejected
	}
	return b, nil
}

func verifyFile(path string, a bootstrap.ReleaseArtifact) error {
	if a.Bytes < 1 || a.Bytes > bootstrap.MaxReleaseAPKBytes {
		return rejected
	}
	f, e := openBounded(path, a.Bytes)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, a.Bytes+1))
	if e != nil || n != a.Bytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return rejected
	}
	return nil
}

func run(args []string, now time.Time, output io.Writer) error {
	if len(args) < 2 || !((args[0] == "sign" && len(args) == 6) || (args[0] == "verify" && len(args) == 4)) {
		return rejected
	}
	raw, e := enrollment.PrivateFile(args[1], 8192)
	var t trustFile
	if e != nil || identity.Decode(raw, &t, true) != nil || t.Floor == nil || t.Anchor.Validate() != nil {
		return rejected
	}
	if args[0] == "verify" {
		wire, e := readSmall(args[2], bootstrap.MaxManifest+1)
		if e != nil {
			return rejected
		}
		m, floor, e := bootstrap.VerifyRelease(string(bytes.TrimSuffix(wire, []byte("\n"))), t.Anchor, t.Scope, *t.Floor, now, now)
		if e != nil || !m.Supports(t.Installed) || verifyFile(args[3], m.APK) != nil {
			return rejected
		}
		return json.NewEncoder(output).Encode(floor)
	}
	raw, e = enrollment.PrivateFile(args[2], 8192)
	var p publication
	if e != nil || identity.Decode(raw, &p, true) != nil {
		return rejected
	}
	inv, e := readSmall(args[3], 16384)
	if e != nil {
		return rejected
	}
	receipt, e := readSmall(args[4], 4096)
	if e != nil {
		return rejected
	}
	m, e := manifest(t, p, inv, receipt)
	if e != nil || !m.Supports(t.Installed) || verifyFile(args[5], m.APK) != nil {
		return rejected
	}
	key, e := enrollment.PrivateKey(os.Getenv("SYN443_APK_RELEASE_KEY_FILE"))
	if e != nil {
		return rejected
	}
	wire, e := bootstrap.SignRelease(m, t.Anchor, key, t.Scope, now)
	if e != nil {
		return rejected
	}
	if _, _, e = bootstrap.VerifyRelease(wire, t.Anchor, t.Scope, *t.Floor, now, now); e != nil {
		return rejected
	}
	_, e = fmt.Fprintln(output, wire)
	return e
}
func main() {
	if run(os.Args[1:], time.Now(), os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "APK release rejected. Usage: apk-release sign TRUST OFFER INVENTORY SIGNING-RECEIPT APK, or apk-release verify TRUST ENVELOPE APK")
		os.Exit(1)
	}
}
