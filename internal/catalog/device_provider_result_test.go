package catalog

import (
	"encoding/binary"
	"net/http"
	"testing"
)

func fixtureProviderResult(metadata, body string) []byte {
	p := append([]byte{}, deviceProviderMagic...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(metadata)))
	return append(append(p, metadata...), body...)
}

func TestVersionedDeviceProviderResultBoundsAndLegacyBody(t *testing.T) {
	const body = "http://proxy.example.invalid:443"
	for _, input := range [][]byte{[]byte(body), fixtureProviderResult(`{"status":200,"etag":"W/\"known\""}`, body)} {
		metadata, read, err := readDeviceProviderResult(input)
		if err != nil || metadata.Status != http.StatusOK || string(read) != body {
			t.Fatal("valid provider body was lost")
		}
	}
	result, read, err := readDeviceProviderResult(fixtureProviderResult(`{"status":304}`, ""))
	if err != nil || result.Status != http.StatusNotModified || len(read) != 0 {
		t.Fatal("valid 304 frame was lost")
	}
	result, read, err = readDeviceProviderResult(fixtureProviderResult(`{"status":410}`, ""))
	if err != nil || result.Status != http.StatusGone || len(read) != 0 {
		t.Fatal("body-free revocation status was lost")
	}
	for _, invalid := range [][]byte{
		fixtureProviderResult(`{"status":304}`, body),
		fixtureProviderResult(`{"status":200}`, ""),
		fixtureProviderResult(`{"status":200,"ETag":"\"uppercase\""}`, body),
		fixtureProviderResult(`{"status":200,"status":304}`, body),
		fixtureProviderResult(`{"status":200,"etag":"\"header\r\nInjection\""}`, body),
		fixtureProviderResult(`{"status":200,"lastModified":"bad-date"}`, body),
		fixtureProviderResult(`{"status":200,"quota":"\tbad"}`, body),
		fixtureProviderResult(`{"status":200,"etag":null}`, body),
		fixtureProviderResult(`{"status":410}`, body),
		fixtureProviderResult(`{"status":410,"etag":""}`, ""),
		append([]byte{0}, []byte(body)...),
	} {
		if _, _, err := readDeviceProviderResult(invalid); err == nil {
			t.Fatal("invalid versioned result accepted")
		}
	}
}
