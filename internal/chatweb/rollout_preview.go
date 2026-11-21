package chatweb

import (
	"net/http"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func previewDeviceRollouts(w http.ResponseWriter, raw []byte) {
	var input struct {
		Device        string                       `json:"device"`
		Decision      *configuration.DeviceRollout `json:"decision"`
		ProbeCooldown *configuration.DeviceRollout `json:"probeCooldown"`
	}
	if identity.DecodeConfiguration(raw, &input) != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	result, err := configuration.PreviewDeviceRollouts(input.Device, input.Decision, input.ProbeCooldown)
	if err != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	reply(w, result)
}
