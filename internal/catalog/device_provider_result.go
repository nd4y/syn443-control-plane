package catalog

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nd4y/syn443-control-plane/internal/identity"
	"github.com/nd4y/syn443-control-plane/internal/subscriptions"
)

const deviceResultMetadataLimit = 4096
const MaxDeviceFetchWireBytes = MaxDeviceFetchBytes + deviceResultMetadataLimit + 8

// The leading NUL is invalid at the start of a legacy subscription body.
var deviceProviderMagic = []byte{0, 'S', '4', '4', '3', 2}

type DeviceFetchValidators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

func (DeviceFetchValidators) String() string   { return "DeviceFetchValidators([redacted])" }
func (DeviceFetchValidators) GoString() string { return "DeviceFetchValidators([redacted])" }

type deviceProviderMetadata struct {
	Status       int    `json:"status"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Quota        string `json:"quota,omitempty"`
}

func validDeviceValidators(v DeviceFetchValidators) bool {
	if v.ETag != "" {
		tag := strings.TrimPrefix(v.ETag, "W/")
		if len(v.ETag) > 512 || len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
			return false
		}
		for _, ch := range tag[1 : len(tag)-1] {
			if ch < '!' || ch > '~' || ch == '"' {
				return false
			}
		}
	}
	if v.LastModified != "" {
		if len(v.LastModified) > 128 {
			return false
		}
		if _, err := http.ParseTime(v.LastModified); err != nil {
			return false
		}
	}
	return true
}

func (v deviceProviderMetadata) validators() DeviceFetchValidators {
	return DeviceFetchValidators{ETag: v.ETag, LastModified: v.LastModified}
}

func DeviceFetchPayloadIsVersioned(raw []byte) bool {
	return len(raw) > 0 && raw[0] == 0
}

// readDeviceProviderResult returns raw provider bytes unchanged for version 1.
// Version 2 binds metadata to the same signed and encrypted result as the body.
func readDeviceProviderResult(raw []byte) (deviceProviderMetadata, []byte, error) {
	metadata := deviceProviderMetadata{Status: http.StatusOK}
	if !DeviceFetchPayloadIsVersioned(raw) {
		if len(raw) == 0 || len(raw) > MaxDeviceFetchBytes {
			return metadata, nil, ErrInvalid
		}
		return metadata, raw, nil
	}
	prefix := len(deviceProviderMagic) + 2
	if len(raw) <= prefix || len(raw) > MaxDeviceFetchWireBytes || !bytes.HasPrefix(raw, deviceProviderMagic) {
		return metadata, nil, ErrInvalid
	}
	size := int(binary.BigEndian.Uint16(raw[len(deviceProviderMagic):prefix]))
	if size == 0 || size > deviceResultMetadataLimit || len(raw) < prefix+size {
		return metadata, nil, ErrInvalid
	}
	encoded := raw[prefix : prefix+size]
	var fields map[string]json.RawMessage
	if identity.DecodeConfiguration(encoded, &fields) != nil || fields == nil {
		return metadata, nil, ErrInvalid
	}
	for name, value := range fields {
		if (name != "status" && name != "etag" && name != "lastModified" && name != "quota") ||
			bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return metadata, nil, ErrInvalid
		}
	}
	metadata = deviceProviderMetadata{}
	if json.Unmarshal(encoded, &metadata) != nil ||
		!validDeviceValidators(metadata.validators()) || len(metadata.Quota) > 1024 ||
		strings.IndexFunc(metadata.Quota, func(r rune) bool { return r < 32 || r > 126 }) >= 0 {
		return metadata, nil, ErrInvalid
	}
	body := raw[prefix+size:]
	switch metadata.Status {
	case http.StatusOK:
		if len(body) == 0 || len(body) > MaxDeviceFetchBytes {
			return metadata, nil, ErrInvalid
		}
	case http.StatusNotModified:
		if len(body) != 0 {
			return metadata, nil, ErrInvalid
		}
	default:
		if !providerErrorStatus(metadata.Status) || len(body) != 0 || len(fields) != 1 {
			return metadata, nil, ErrInvalid
		}
	}
	return metadata, body, nil
}

func providerErrorStatus(status int) bool {
	return status == 401 || status == 403 || status == 404 || status == 410 || status == 429 || status >= 500 && status <= 599
}

func (v deviceProviderMetadata) cache() subscriptions.Cache {
	return subscriptions.Cache{ETag: v.ETag, LastModified: v.LastModified}
}
