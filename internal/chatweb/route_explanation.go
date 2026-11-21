package chatweb

import (
	"net/http"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/identity"
)

const routeExplanationLimit = 262144

// The operator supplies only rule predicates, outbound tags and connection
// metadata. This path neither loads credentials nor records a destination.
func explainDraftRoute(w http.ResponseWriter, raw []byte) {
	var input struct {
		Rules      []configuration.RouteRule  `json:"rules"`
		DNSRules   []configuration.DNSRule    `json:"dnsRules"`
		RouteFinal string                     `json:"routeFinal"`
		DNSFinal   string                     `json:"dnsFinal"`
		Query      configuration.TrafficQuery `json:"query"`
	}
	if identity.DecodeConfiguration(raw, &input) != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	result, err := configuration.ExplainTraffic(configuration.NetworkSettings{
		SchemaVersion: 1, Rules: input.Rules, DNSRules: input.DNSRules, DNSFinal: input.DNSFinal,
	}, input.RouteFinal, input.Query)
	if err != nil {
		fail(w, http.StatusBadRequest)
		return
	}
	reply(w, result)
}
