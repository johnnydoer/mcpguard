package audit

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/JohnnyDoer/mcpguard/internal/enforce"
)

// Metrics exports decision counters and latency as Prometheus metrics.
//
// Labels are restricted to values that come from configuration — decision,
// rule, server, tool. Nothing derived from arguments may become a label: one
// series per distinct path would make cardinality unbounded and take the
// Prometheus instance with it.
type Metrics struct {
	decisions *prometheus.CounterVec
	latency   *prometheus.HistogramVec
}

// NewMetrics registers the mcpguard Prometheus collectors with reg and returns
// a Metrics recorder ready to accept events.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpguard_decisions_total",
			Help: "Policy decisions by outcome.",
		}, []string{"decision", "rule", "server", "tool"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mcpguard_policy_eval_seconds",
			Help: "Time spent evaluating policy, including any approval wait.",
			// Buckets span sub-millisecond evaluation through a full approval
			// wait, because both land in this histogram.
			Buckets: []float64{0.0001, 0.001, 0.01, 0.1, 1, 10, 60, 300},
		}, []string{"server", "method"}),
	}

	for _, c := range []prometheus.Collector{m.decisions, m.latency} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("audit: register metric: %w", err)
		}
	}
	return m, nil
}

// Record implements enforce.Recorder.
func (m *Metrics) Record(ev enforce.Event) error {
	rule := ev.Decision.Rule
	if rule == "" {
		// A stable placeholder rather than an empty label, so a default-deny is
		// distinguishable from a missing value in a Grafana query.
		rule = "<default>"
	}
	m.decisions.WithLabelValues(string(ev.Decision.Action), rule, ev.Server, ev.Tool).Inc()
	m.latency.WithLabelValues(ev.Server, ev.Method).Observe(ev.Latency.Seconds())
	return nil
}

type multiRecorder struct {
	recorders []enforce.Recorder
}

// MultiRecorder fans an event out to several recorders.
//
// Every recorder runs even if an earlier one fails, so a full disk stops the
// audit log without also stopping metrics. The first error is returned so
// audit.on_error still applies.
func MultiRecorder(recorders ...enforce.Recorder) enforce.Recorder {
	return &multiRecorder{recorders: recorders}
}

func (m *multiRecorder) Record(ev enforce.Event) error {
	var firstErr error
	for _, r := range m.recorders {
		if err := r.Record(ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
