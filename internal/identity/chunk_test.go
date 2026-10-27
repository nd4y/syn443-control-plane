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
