package deviceprovisioning

import (
	"encoding/json"
	"testing"

	"github.com/nd4y/syn443-control-plane/internal/configuration"
	"github.com/nd4y/syn443-control-plane/internal/enrollment"
	"github.com/nd4y/syn443-control-plane/internal/policy"
)

func TestLayerPublisherDependencyFingerprintBindsAlgorithmWithEqualEngineBytes(t *testing.T) {
	target := enrollment.ConfigurationTarget{Device: "device-a"}
	prepared := &enrollment.PreparedConfiguration{EngineConfig: json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"}]}`), AlgorithmRevision: configuration.AdaptiveTCPAlgorithm,
		RequiredCapabilities: adaptiveAuthorityCapabilities(), Activation: policy.Gate{TimeoutSeconds: 30}, Fence: &networkFence{}}
	first, err := layerDependency(target, prepared)
	if err != nil || first.AlgorithmRevision != configuration.AdaptiveTCPAlgorithm {
		t.Fatal("actual layer dependency omitted algorithm", err)
	}
	hash, err := layerDependencyHash("same-layers", []configurationLayerDependency{first})
	if err != nil {
		t.Fatal(err)
	}
	prepared.AlgorithmRevision = policy.ConfirmedFailoverAlgorithm
	second, err := layerDependency(target, prepared)
	if err != nil || first.EngineHash != second.EngineHash || first.ActivationHash != second.ActivationHash {
		t.Fatal("fixture changed engine/activation rather than algorithm", err)
	}
	changed, err := layerDependencyHash("same-layers", []configurationLayerDependency{second})
	if err != nil || changed == hash {
		t.Fatal("signed preview dependency accepted another algorithm with identical engine bytes", err)
	}
	prepared.RequiredCapabilities[0] = "changed.v1"
	if first.Capabilities[0] != "engine-config.v1" || second.Capabilities[0] != "engine-config.v1" {
		t.Fatal("mutable prepared capability slice changed the preview dependency")
	}
	if unchanged, err := layerDependencyHash("same-layers", []configurationLayerDependency{first}); err != nil || unchanged != hash {
		t.Fatal("owned dependency fingerprint changed after further preparation", err)
	}
	prepared.Fence = nil
	if _, err := layerDependency(target, prepared); err == nil {
		t.Fatal("unfenced configuration entered preview dependencies")
	}
}
