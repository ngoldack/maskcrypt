package maskcryptprocessor

import (
	"context"
	"fmt"

	"github.com/ngoldack/maskcrypt/engine"
	"github.com/ngoldack/maskcrypt/parser"
	"github.com/ngoldack/maskcrypt/processor/maskcryptprocessor/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

func NewFactory() processor.Factory {
	return processor.NewFactory(
		metadata.Type,
		createDefaultConfig,
		processor.WithTraces(createTracesProcessor, metadata.TracesStability),
		processor.WithLogs(createLogsProcessor, metadata.LogsStability),
		processor.WithMetrics(createMetricsProcessor, metadata.MetricsStability),
	)
}

// Note: This isn't a valid configuration because the processor would do no work.
func createDefaultConfig() component.Config {
	return &Config{}
}

func createTracesProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Traces,
) (processor.Traces, error) {
	c := cfg.(*Config)

	engines, err := engine.GetEngines(&c.MaskCryptConfig)
	if err != nil {
		return nil, fmt.Errorf("error getting engines: %w", err)
	}

	reg := engine.NewEngineRegistry(engines...)
	p, err := parser.NewDefaultParser(reg)
	if err != nil {
		return nil, fmt.Errorf("error creating a parser: %w", err)
	}

	mcrypt, err := newMaskcryptProcessor(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("error creating a maskcrypt processor: %w", err)
	}

	return processorhelper.NewTraces(
		ctx,
		set,
		cfg,
		next,
		mcrypt.processTraces(),
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createMetricsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Metrics,
) (processor.Metrics, error) {
	c := cfg.(*Config)

	engines, err := engine.GetEngines(&c.MaskCryptConfig)
	if err != nil {
		return nil, fmt.Errorf("error getting engines: %w", err)
	}

	reg := engine.NewEngineRegistry(engines...)
	p, err := parser.NewDefaultParser(reg)
	if err != nil {
		return nil, fmt.Errorf("error creating a parser: %w", err)
	}

	mcrypt, err := newMaskcryptProcessor(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("error creating a maskcrypt processor: %w", err)
	}

	return processorhelper.NewMetrics(
		ctx,
		set,
		cfg,
		next,
		mcrypt.processMetrics(),
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createLogsProcessor(
	ctx context.Context,
	set processor.Settings,
	cfg component.Config,
	next consumer.Logs,
) (processor.Logs, error) {
	c := cfg.(*Config)

	engines, err := engine.GetEngines(&c.MaskCryptConfig)
	if err != nil {
		return nil, fmt.Errorf("error getting engines: %w", err)
	}

	reg := engine.NewEngineRegistry(engines...)
	p, err := parser.NewDefaultParser(reg)
	if err != nil {
		return nil, fmt.Errorf("error creating a parser: %w", err)
	}

	mcrypt, err := newMaskcryptProcessor(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("error creating a maskcrypt processor: %w", err)
	}

	return processorhelper.NewLogs(
		ctx,
		set,
		cfg,
		next,
		mcrypt.processLogs(),
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}
