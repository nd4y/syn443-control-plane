package identity

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAttachmentDecoderDoesNotExpandIdentityLimits(t *testing.T) {
	type part struct {
		Data []byte `json:"data"`
	}
	raw, _ := json.Marshal(part{bytes.Repeat([]byte{37}, 256*1024)})
	var out part
	if Decode(raw, &out, true) == nil {
		t.Fatal("ordinary identity budget enlarged")
	}
	if DecodeAttachmentChunk(raw, &out) != nil || len(out.Data) != 256*1024 {
		t.Fatal("bounded chunk")
	}
	for _, invalid := range [][]byte{append(raw, []byte(` {}`)...), []byte(`{"data":"AA==","data":"AA=="}`), []byte(`{"data":"AA==","unknown":1}`), bytes.Repeat([]byte{'x'}, 352*1024+1)} {
		if DecodeAttachmentChunk(invalid, &out) == nil {
			t.Fatal("invalid envelope")
		}
	}
}

func TestSourceUploadHasAnIndependentClosedBudget(t *testing.T) {
	type source struct {
		Data []byte `json:"data"`
	}
	raw, _ := json.Marshal(source{bytes.Repeat([]byte{37}, 1024*1024)})
	var out source
	if Decode(raw, &out, true) == nil || DecodeAttachmentChunk(raw, &out) == nil {
		t.Fatal("source upload expanded another protocol budget")
	}
	if DecodeSourceUpload(raw, &out) != nil || len(out.Data) != 1024*1024 {
		t.Fatal("bounded source upload")
	}
	for _, invalid := range [][]byte{[]byte(`{"Data":"AA=="}`), []byte(`{"data":"AA==","data":"AA=="}`), []byte(`{"data":"AA==","extra":true}`), bytes.Repeat([]byte{'x'}, 14*1024*1024+65537)} {
		if DecodeSourceUpload(invalid, &out) == nil {
			t.Fatal("source envelope boundary")
		}
	}
}
