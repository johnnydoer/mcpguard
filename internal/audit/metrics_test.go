package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

func TestMetricsCountsDecisions(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Record(sampleEvent()); err != nil {
		t.Fatal(err)
	}

	want := `
# HELP mcpguard_decisions_total Policy decisions by outcome.
# TYPE mcpguard_decisions_total counter
mcpguard_decisions_total{decision="allow",rule="allow-public",server="fs",tool="read_file"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"mcpguard_decisions_total"); err != nil {
		t.Error(err)
	}
}

func TestMetricsObservesLatency(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, _ := NewMetrics(reg)
	ev := sampleEvent()
	ev.Latency = 5 * time.Millisecond
	_ = m.Record(ev)

	if got := testutil.CollectAndCount(reg, "mcpguard_policy_eval_seconds"); got == 0 {
		t.Error("latency histogram was not populated")
	}
}

func TestMultiRecorderFansOut(t *testing.T) {
	a, b := &countingRecorder{}, &countingRecorder{}
	if err := MultiRecorder(a, b).Record(sampleEvent()); err != nil {
		t.Fatal(err)
	}
	if a.n != 1 || b.n != 1 {
		t.Errorf("a=%d b=%d, want both 1", a.n, b.n)
	}
}

func TestMultiRecorderReturnsTheFirstErrorButStillFansOut(t *testing.T) {
	// The audit log failing must not stop metrics being recorded, and the error
	// must still reach the caller so audit.on_error can apply.
	failing := &countingRecorder{err: errors.New("disk full")}
	ok := &countingRecorder{}

	err := MultiRecorder(failing, ok).Record(sampleEvent())
	if err == nil {
		t.Error("the error must propagate so on_error can apply")
	}
	if ok.n != 1 {
		t.Error("a later recorder must still run after an earlier one fails")
	}
}

func TestMetricsCardinalityIsBounded(t *testing.T) {
	// One series per CVE-style unbounded label would blow up Prometheus. Rule and
	// tool names come from config and are bounded; nothing derived from arguments
	// may become a label.
	reg := prometheus.NewRegistry()
	m, _ := NewMetrics(reg)
	for i := 0; i < 50; i++ {
		ev := sampleEvent()
		ev.Args = map[string]any{"path": strings.Repeat("x", i)}
		_ = m.Record(ev)
	}
	if got := testutil.CollectAndCount(reg, "mcpguard_decisions_total"); got != 1 {
		t.Errorf("series count = %d, want 1; an argument value leaked into a label", got)
	}
}

type countingRecorder struct {
	n   int
	err error
}

func (c *countingRecorder) Record(enforce.Event) error {
	c.n++
	return c.err
}

var _ policy.Mode = policy.ModeEnforce
