package chatweb

import (
	"context"
	"net/http"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

func reviewGroupNetworkImpact(ctx context.Context, w http.ResponseWriter, raw []byte) {
	var input struct {
		Bundles       []configuration.LayerBundle `json:"bundles"`
		EffectiveHash string                      `json:"effectiveHash"`
	}
	if identity.DecodeConfiguration(raw, &input) != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	impacts, err := configuration.ReviewGroupNetworkImpact(ctx, input.Bundles, input.EffectiveHash)
	if err != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	reply(w, struct {
		EffectiveHash string                             `json:"effectiveHash"`
		Recipients    []configuration.GroupNetworkImpact `json:"recipients"`
	}{input.EffectiveHash, impacts})
}
