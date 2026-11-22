package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"time"

	"github.com/nd4y/syn443-control-plane/internal/policy"
)

const releaseType = "syn443-apk-release+jws"
const MaxReleaseAPKBytes = 256 << 20
const maxReleaseCounter = 9007199254740991

var releaseSHA = regexp.MustCompile("^[0-9a-f]{64}$")
var releaseCommit = regexp.MustCompile("^[0-9a-f]{40}$")
var moduleName = regexp.MustCompile("^[A-Za-z0-9._-]{1,64}$")

// The approved recipient, channel and APK signing identity come from the operator
// or the installed client. The envelope cannot select the release verification key.
type ReleaseScope struct {
	ServiceID    string `json:"serviceId"`
	DeviceID     string `json:"deviceId"`
	Channel      string `json:"channel"`
	SignerSHA256 string `json:"signerCertificateSha256"`
}

type ReleaseArtifact struct {
	Package            string            `json:"package"`
	VersionCode        int64             `json:"versionCode"`
	MinSDK             int               `json:"minSdk"`
	TargetSDK          int               `json:"targetSdk"`
	NativeLibraries    map[string]string `json:"nativeLibraries"`
	SHA256             string            `json:"sha256"`
	Bytes              int64             `json:"bytes"`
	SourceCommit       string            `json:"sourceCommit"`
	EngineLockSHA256   string            `json:"engineLockSha256"`
	ContractLockSHA256 string            `json:"contractLockSha256"`
}

type ReleaseCompatibility struct {
	MinimumInstalledVersion int64    `json:"minimumInstalledVersionCode"`
	EngineCapabilities      []string `json:"engineCapabilities"`
	Evaluators              []string `json:"evaluators"`
	Schemas                 []string `json:"schemas"`
}

type ReleaseManifest struct {
	SchemaVersion   int                  `json:"schemaVersion"`
	Audience        string               `json:"audience"`
	Scope           ReleaseScope         `json:"scope"`
	RootEpoch       int64                `json:"rootEpoch"`
	SecurityEpoch   int64                `json:"securityEpoch"`
	Revision        int64                `json:"revision"`
	RevocationFloor int64                `json:"revocationFloor"`
	IssuedAt        int64                `json:"issuedAt"`
	NotBefore       int64                `json:"notBefore"`
	Expires         int64                `json:"expires"`
	APK             ReleaseArtifact      `json:"apk"`
	Compatibility   ReleaseCompatibility `json:"compatibility"`
}

// The zero value is an empty journal. Persist the returned floor with the
// accepted manifest. Preserve it across retries and metadata key rotation.
type ReleaseFloor struct {
	Scope           ReleaseScope `json:"scope"`
	RootEpoch       int64        `json:"rootEpoch"`
	SecurityEpoch   int64        `json:"securityEpoch"`
	Revision        int64        `json:"revision"`
	RevocationFloor int64        `json:"revocationFloor"`
	PayloadSHA256   string       `json:"payloadSha256"`
}

func releaseNames(names []string) bool {
	if len(names) < 1 || len(names) > 32 || !slices.IsSorted(names) {
		return false
	}
	for i, n := range names {
		if !moduleName.MatchString(n) || (i > 0 && n == names[i-1]) {
			return false
		}
	}
	return true
}

func (m ReleaseManifest) validate(anchor Anchor, expected ReleaseScope, lower, upper time.Time) error {
	device, err := base64.RawURLEncoding.Strict().DecodeString(expected.DeviceID)
	if err != nil || len(device) != 32 || base64.RawURLEncoding.EncodeToString(device) != expected.DeviceID {
		return ErrUntrusted
	}
	a, c := m.APK, m.Compatibility
	if m.SchemaVersion != 1 || m.Audience != "syn443-device-release" || m.Scope != expected ||
		!identifier.MatchString(expected.ServiceID) || !digestID.MatchString(expected.DeviceID) ||
		!identifier.MatchString(expected.Channel) || !releaseSHA.MatchString(expected.SignerSHA256) ||
		anchor.Epoch != m.RootEpoch || m.SecurityEpoch < 1 || m.SecurityEpoch > maxReleaseCounter ||
		m.Revision < 1 || m.Revision > maxReleaseCounter || m.RevocationFloor < 0 || m.RevocationFloor > m.Revision ||
		lower.After(upper) || m.IssuedAt < 1 || m.IssuedAt > m.NotBefore || m.NotBefore > lower.Unix() ||
		m.Expires <= upper.Unix() || m.Expires > maxReleaseCounter || m.Expires-m.IssuedAt > 7*24*3600 ||
		a.Package != "io.syn443.android" || a.VersionCode < 2 || a.VersionCode > 2100000000 ||
		a.MinSDK < 29 || a.MinSDK > a.TargetSDK || a.TargetSDK > 100 ||
		a.Bytes < 1 || a.Bytes > MaxReleaseAPKBytes || !releaseSHA.MatchString(a.SHA256) ||
		!releaseCommit.MatchString(a.SourceCommit) || !releaseSHA.MatchString(a.EngineLockSHA256) ||
		!releaseSHA.MatchString(a.ContractLockSHA256) || len(a.NativeLibraries) == 0 || len(a.NativeLibraries) > 2 ||
		c.MinimumInstalledVersion < 1 || c.MinimumInstalledVersion >= a.VersionCode ||
		!releaseNames(c.EngineCapabilities) || !releaseNames(c.Evaluators) || !releaseNames(c.Schemas) {
		return ErrUntrusted
	}
	for abi, hash := range a.NativeLibraries {
		if (abi != "arm64-v8a" && abi != "x86_64") || !releaseSHA.MatchString(hash) {
			return ErrUntrusted
		}
	}
	return nil
}

// SignRelease is an offline typed operation. A release key is supplied independently
// of both the Android package certificate and the enrollment/policy key rings.
func SignRelease(m ReleaseManifest, anchor Anchor, key *ecdsa.PrivateKey, scope ReleaseScope, now time.Time) (string, error) {
	if m.validate(anchor, scope, now, now) != nil {
		return "", ErrUntrusted
	}
	return sign(m, releaseType, anchor, key)
}

func VerifyRelease(raw string, anchor Anchor, scope ReleaseScope, floor ReleaseFloor, lower, upper time.Time) (ReleaseManifest, ReleaseFloor, error) {
	var m ReleaseManifest
	body, err := verify(raw, releaseType, anchor, &m)
	if err != nil || m.validate(anchor, scope, lower, upper) != nil {
		return ReleaseManifest{}, floor, ErrUntrusted
	}
	// Require every field, including zero-valued floors, and exact JSON member names.
	encoded, err := json.Marshal(m)
	canonical, canonicalErr := policy.Canonical(encoded)
	if err != nil || canonicalErr != nil || !bytes.Equal(canonical, body) {
		return ReleaseManifest{}, floor, ErrUntrusted
	}
	sum := sha256.Sum256(body)
	next := ReleaseFloor{scope, m.RootEpoch, m.SecurityEpoch, m.Revision, m.RevocationFloor, hex.EncodeToString(sum[:])}
	if floor != (ReleaseFloor{}) && (floor.Scope != scope || !releaseSHA.MatchString(floor.PayloadSHA256) ||
		floor.RootEpoch < 1 || floor.SecurityEpoch < 1 || floor.Revision < 1 || floor.RevocationFloor < 0 || floor.RevocationFloor > floor.Revision ||
		next.RootEpoch < floor.RootEpoch || next.SecurityEpoch < floor.SecurityEpoch || next.Revision < floor.Revision ||
		next.RevocationFloor < floor.RevocationFloor || next.Revision == floor.Revision && next != floor) {
		return ReleaseManifest{}, floor, ErrUntrusted
	}
	return m, next, nil
}

// InstalledReleaseContext is observed independently of the update offer.
// SDK levels above the APK target can still run the APK.
type InstalledReleaseContext struct {
	VersionCode                int64    `json:"versionCode"`
	SDK                        int      `json:"sdk"`
	ABIs                       []string `json:"abis"`
	RequiredEngineCapabilities []string `json:"requiredEngineCapabilities"`
	Evaluator                  string   `json:"evaluator"`
	Schema                     string   `json:"schema"`
}

func (m ReleaseManifest) Supports(installed InstalledReleaseContext) bool {
	c := m.Compatibility
	if installed.VersionCode < c.MinimumInstalledVersion || installed.VersionCode >= m.APK.VersionCode ||
		installed.SDK < m.APK.MinSDK || len(installed.ABIs) < 1 || len(installed.ABIs) > 16 ||
		len(installed.RequiredEngineCapabilities) > 32 || !slices.Contains(c.Evaluators, installed.Evaluator) ||
		!slices.Contains(c.Schemas, installed.Schema) {
		return false
	}
	for _, capability := range installed.RequiredEngineCapabilities {
		if !slices.Contains(c.EngineCapabilities, capability) {
			return false
		}
	}
	for _, abi := range installed.ABIs {
		if _, ok := m.APK.NativeLibraries[abi]; ok {
			return true
		}
	}
	return false
}
