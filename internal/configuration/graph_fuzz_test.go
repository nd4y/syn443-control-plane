package configuration

import "testing"

func FuzzConfigurationGraph(f *testing.F) {
	for _, seed := range []string{`{"profiles":{},"chains":{},"balancers":{},"final":"direct"}`, `{"chains":{"alias":{"dialOrder":["direct"]}},"final":"alias"}`, `{"balancers":{"choice":{"type":"selector","members":["direct"],"interruptExisting":false}},"final":"choice"}`, `{"balancers":{"cycle":{"type":"selector","members":["cycle"],"interruptExisting":false}},"final":"cycle"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32768 {
			return
		}
		graph, e := DecodeGraph(raw)
		if e != nil {
			return
		}
		_, _ = CompileGraph(graph, nil)
	})
}
