package decision

import (
	"errors"
	"regexp"
	"sync"
)

const MaxGeneration = int64(2147483647)

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Snapshot struct {
	Context      Context
	DesiredOn    bool
	ActivePathID string
}
type Coordinator struct {
	mu    sync.Mutex
	state Snapshot
}

func validContext(c Context) bool {
	return c.NetworkEpoch >= 0 && c.NetworkEpoch <= MaxGeneration && c.ActivationGeneration >= 0 && c.ActivationGeneration <= MaxGeneration && c.EngineGeneration >= 0 && c.EngineGeneration <= MaxGeneration && identifier.MatchString(c.ConfigRevision) && identifier.MatchString(c.AlgorithmRevision) && digest.MatchString(c.DependencyHash)
}
func NewCoordinator(c Context) (*Coordinator, error) {
	if !validContext(c) {
		return nil, errors.New("invalid context")
	}
	return &Coordinator{state: Snapshot{Context: c}}, nil
}
func (c *Coordinator) Snapshot() Snapshot { c.mu.Lock(); defer c.mu.Unlock(); return c.state }
func (c *Coordinator) intent(on bool) (Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Context.ActivationGeneration == MaxGeneration {
		if !on {
			c.state.DesiredOn = false
			c.state.ActivePathID = ""
			return c.state.Context, nil
		}
		return c.state.Context, errors.New("generation exhausted")
	}
	c.state.Context.ActivationGeneration++
	c.state.DesiredOn = on
	c.state.ActivePathID = ""
	return c.state.Context, nil
}
func (c *Coordinator) Start() (Context, error) { return c.intent(true) }
func (c *Coordinator) Stop() (Context, error)  { return c.intent(false) }
func (c *Coordinator) NetworkChanged() (Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Context.NetworkEpoch == MaxGeneration {
		return c.state.Context, errors.New("generation exhausted")
	}
	c.state.Context.NetworkEpoch++
	c.state.ActivePathID = ""
	return c.state.Context, nil
}
func (c *Coordinator) EngineChanged() (Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Context.EngineGeneration == MaxGeneration {
		return c.state.Context, errors.New("generation exhausted")
	}
	c.state.Context.EngineGeneration++
	c.state.ActivePathID = ""
	return c.state.Context, nil
}
func (c *Coordinator) Activate(config, algorithm, hash string) (Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !identifier.MatchString(config) || !identifier.MatchString(algorithm) || !digest.MatchString(hash) {
		return c.state.Context, errors.New("invalid activation")
	}
	if c.state.Context.ActivationGeneration == MaxGeneration {
		return c.state.Context, errors.New("generation exhausted")
	}
	c.state.Context.ActivationGeneration++
	c.state.Context.ConfigRevision = config
	c.state.Context.AlgorithmRevision = algorithm
	c.state.Context.DependencyHash = hash
	c.state.ActivePathID = ""
	return c.state.Context, nil
}
func (c *Coordinator) TryApply(token Context, pathID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.DesiredOn || token != c.state.Context || !identifier.MatchString(pathID) {
		return false
	}
	c.state.ActivePathID = pathID
	return true
}
