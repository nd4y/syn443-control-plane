package main

import (
	"context"

	"github.com/nd4y/syn443-control-plane/internal/health"
)

func checkReady(ctx context.Context, c config) error {
	return health.ProbeLocalService(ctx, health.LoopbackProbe{
		Listen: c.Listen, Origin: c.Origin, Certificate: c.Certificate, ServerName: c.ReadinessServerName, FixtureHTTP: c.FixtureHTTP,
	}, "telemetry-ingest")
}
