package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/Checkmarx/kics/internal/metrics"
	"github.com/Checkmarx/kics/pkg/kics"
	"github.com/Checkmarx/kics/pkg/progress"
)

type serviceSlice []*kics.Service

func PrepareAndScan(ctx context.Context, scanID string, proBarBuilder progress.PbBuilder, services serviceSlice) error {
	metrics.Metric.Start("prepare_sources")
	var wg sync.WaitGroup
	wgDone := make(chan bool)
	errCh := make(chan error)
	var wgProg sync.WaitGroup

	for _, service := range services {
		wg.Add(1)
		go service.PrepareSources(ctx, scanID, &wg, errCh)
	}

	go func() {
		defer func() {
			close(wgDone)
		}()
		wg.Wait()
		wgProg.Wait()
	}()

	select {
	case <-wgDone:
		metrics.Metric.Stop()
		err := StartScan(ctx, scanID, proBarBuilder, services)
		if err != nil {
			return err
		}
		break
	case err := <-errCh:
		close(errCh)
		return err
	}
	return nil
}

// StartScan will run concurrent scans by parser
func StartScan(ctx context.Context, scanID string, proBarBuilder progress.PbBuilder, services serviceSlice) error {
	defer metrics.Metric.Stop()
	metrics.Metric.Start("start_scan")
	var wg sync.WaitGroup
	wgDone := make(chan bool)
	errCh := make(chan error)
	currentQuery := make(chan int64, 1)
	var wgProg sync.WaitGroup

	total := services.GetQueriesLength()
	if total != 0 {
		startProgressBar(total, &wgProg, currentQuery, proBarBuilder)
	}

	for _, service := range services {
		wg.Add(1)
		go service.StartScan(ctx, scanID, errCh, &wg, currentQuery)
	}

	go func() {
		defer func() {
			close(wgDone)
			fmt.Println("\r")
		}()
		wg.Wait()
		wgProg.Wait()
	}()

	select {
	case <-wgDone:
		break
	case err := <-errCh:
		close(errCh)
		return err
	}
	close(currentQuery)
	return nil
}

// GetQueriesLength returns the Total of queries for all Services
func (s serviceSlice) GetQueriesLength() int {
	count := 0
	for _, service := range s {
		if service.Inspector != nil {
			count += service.Inspector.LenQueriesByPlat(service.Parser.Platform)
		}
		if service.SecretsInspector != nil {
			count += service.SecretsInspector.GetQueriesLength()
		}
		if service.GptInspector != nil {
			count += service.GptInspector.GetPromptsLength()
		}
	}
	return count
}

func startProgressBar(total int, wg *sync.WaitGroup, progressChannel chan int64, proBarBuilder progress.PbBuilder) {
	wg.Add(1)
	progressBar := proBarBuilder.BuildCounter("Executing queries: ", total, wg, progressChannel)
	go progressBar.Start()
}
