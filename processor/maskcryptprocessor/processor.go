package maskcryptprocessor

import (
	"context"

	"github.com/ngoldack/maskcrypt/parser"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

type maskcryptProcessor struct {
	parser parser.Parser
}

func newMaskcryptProcessor(_ context.Context, p parser.Parser) (*maskcryptProcessor, error) {
	return &maskcryptProcessor{parser: p}, nil
}

func (mp *maskcryptProcessor) processTraces() processorhelper.ProcessTracesFunc {
	return func(ctx context.Context, t ptrace.Traces) (ptrace.Traces, error) {
		for _, s := range t.ResourceSpans().All() {
			for ak, av := range s.Resource().Attributes().All() {
				if mp.parser.ShouldMask(ak) {
					masked, err := mp.parser.Mask(ctx, ak, av.Bytes().AsRaw())
					if err != nil {
						// TODO: handle error
						return t, err
					}
					av.Bytes().FromRaw(masked)
				}
			}
		}
		return t, nil
	}

}

func (mp *maskcryptProcessor) processMetrics() processorhelper.ProcessMetricsFunc {
	return func(ctx context.Context, m pmetric.Metrics) (pmetric.Metrics, error) {
		for _, ilm := range m.ResourceMetrics().All() {
			for ak, av := range ilm.Resource().Attributes().All() {
				if mp.parser.ShouldMask(ak) {
					masked, err := mp.parser.Mask(ctx, ak, av.Bytes().AsRaw())
					if err != nil {
						// TODO: handle error
						return m, err
					}
					av.Bytes().FromRaw(masked)
				}
			}
		}
		return m, nil
	}
}

func (mp *maskcryptProcessor) processLogs() processorhelper.ProcessLogsFunc {
	return func(ctx context.Context, l plog.Logs) (plog.Logs, error) {
		for _, ilm := range l.ResourceLogs().All() {
			for ak, av := range ilm.Resource().Attributes().All() {
				if mp.parser.ShouldMask(ak) {
					masked, err := mp.parser.Mask(ctx, ak, av.Bytes().AsRaw())
					if err != nil {
						// TODO: handle error
						return l, err
					}
					av.Bytes().FromRaw(masked)
				}
			}
		}
		return l, nil
	}
}
