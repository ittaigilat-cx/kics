package gpt

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Checkmarx/kics/internal/metrics"
	sentryReport "github.com/Checkmarx/kics/internal/sentry"
	engine "github.com/Checkmarx/kics/pkg/engine"
	"github.com/Checkmarx/kics/pkg/engine/source"
	"github.com/Checkmarx/kics/pkg/model"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type Inspector struct {
	prompts          []model.PromptMetadata
	files            []model.FileAndType
	apiKey           string
	threads          int
	tracker          engine.Tracker
	failedQueries    map[string]error
	excludeResults   map[string]bool
	queryExecTimeout time.Duration
}

type RequestResponse struct {
	SourceFile model.FileMetadata   `json:"sourcefile"`
	PromptFile model.PromptMetadata `json:"promptFile"`
	Prompt     string               `json:"prompt"`
	Platform   string               `json:"platform"`
	Response   string               `json:"response"`
	Result     []Result             `json:"result"`
	Duration   string               `json:"milliseconds"`
}

type Prompt struct {
	SourceFile model.FileMetadata
	PromptFile model.PromptMetadata
	Prompt     string
	Platform   string
}

func NewGptInspector(
	ctx context.Context,
	queriesSource source.QueriesSource,
	apiKey string,
	threads int,
	tracker engine.Tracker,
	excludeResults map[string]bool,
	filesAndTypes []model.FileAndType,
	queryTimeout int) (*Inspector, error) {
	log.Debug().Msg("engine.NewInspector()")

	metrics.Metric.Start("get_prompts")
	prompts, err := queriesSource.GetPrompts()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get prompts")
	}

	failedQueries := make(map[string]error)
	queryExecTimeout := time.Duration(queryTimeout) * time.Second

	return &Inspector{
		prompts:          prompts,
		files:            filesAndTypes,
		apiKey:           apiKey,
		threads:          threads,
		tracker:          tracker,
		failedQueries:    failedQueries,
		excludeResults:   excludeResults,
		queryExecTimeout: queryExecTimeout,
	}, nil
}

func (c *Inspector) GetFailedQueries() map[string]error {
	return c.failedQueries
}

func (c *Inspector) GetFiles() []model.FileAndType {
	return c.files
}

func (c *Inspector) GetPromptsLength() int {
	var count int
	for _, f := range c.files {
		for _, p := range c.prompts {
			if isSamePlatform(p.Platform, f.Type) {
				count++
			}
		}
	}
	return count
}

func isSamePlatform(promptPlatform, filePlatform string) bool {
	return strings.EqualFold(promptPlatform, filePlatform)
}

func (c *Inspector) Inspect(
	ctx context.Context,
	scanID string,
	files model.FileMetadatas,
	currentQuery chan<- int64) ([]model.Vulnerability, error) {
	log.Debug().Msg("gpt.Inspect()")

	vulnerabilities := make([]model.Vulnerability, 0)
	results := c.runGpt(files, currentQuery)
	for _, result := range results {
		if len(result.Result) > 0 {
			for _, res := range result.Result {
				vul := model.Vulnerability{
					ScanID:         scanID,
					FileID:         result.SourceFile.ID,
					FileName:       result.SourceFile.FilePath,
					QueryID:        result.PromptFile.ID,
					QueryName:      result.PromptFile.PromptFile,
					Description:    result.PromptFile.Prompt,
					Platform:       result.Platform,
					Severity:       model.Severity(res.Severity),
					Line:           res.Line,
					IssueType:      model.IssueType(res.QueryName),
					KeyActualValue: result.Response,
				}
				vulnerabilities = append(vulnerabilities, vul)
			}
		}
	}
	return vulnerabilities, nil
}

func (c *Inspector) runGpt(sourceFiles model.FileMetadatas, currentQuery chan<- int64) []RequestResponse {

	prompts := make(chan Prompt)
	responses := make(chan RequestResponse)
	var wg sync.WaitGroup
	var threads int

	if c.threads <= 0 {
		threads = 5
	} else {
		threads = c.threads
	}
	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			for prompt := range prompts {
				start := time.Now()
				response, err := CallGPT(c.apiKey, prompt.Prompt)
				elapsedMilliseconds := time.Since(start).Milliseconds()
				currentQuery <- 1

				if err != nil {
					sentryReport.ReportSentry(&sentryReport.Report{
						Message:  fmt.Sprintf("GPT Inspector. prompt '%s' with error", prompt.PromptFile.PromptFile),
						Err:      err,
						Location: "func Inspect()",
						Platform: prompt.Platform,
						Query:    prompt.PromptFile.PromptFile,
					}, true)

					c.failedQueries[prompt.PromptFile.PromptFile] = err
				}

				// Uncomment for tracing purposes
				// fmt.Printf("File: '%s'\nPrompt: '%s'\nPlatform: '%s'\nResponse: '%s'\nResult(str): '%s'\n",
				// 	prompt.SourceFile.FilePath, prompt.PromptFile.PromptFile, prompt.Platform, response, ExtractResultAsString(response))
				// rs := ExtractResult(response)
				// for i, r := range rs {
				// 	fmt.Printf("[%d] queryName: '%s', severity: '%s', line: '%d', filename: '%s'\n", i, r.QueryName, r.Severity, r.Line, r.Filename)
				// }

				responses <- RequestResponse{
					SourceFile: prompt.SourceFile,
					PromptFile: prompt.PromptFile,
					Prompt:     prompt.Prompt,
					Platform:   prompt.Platform,
					Response:   response,
					Result:     ExtractResult(response),
					Duration:   strconv.FormatInt(elapsedMilliseconds, 10)}
			}
			wg.Done()
		}()
	}

	go GetPrompts(c.prompts, sourceFiles, prompts)

	go func() {
		wg.Wait()
		close(responses)
	}()

	var results []RequestResponse
	for response := range responses {
		results = append(results, response)
	}
	return results
}

func GetPrompts(promptFiles []model.PromptMetadata, sourceFiles model.FileMetadatas, prompts chan<- Prompt) {
	for _, sourceFile := range sourceFiles {
		for _, promptFile := range promptFiles {
			if isSamePlatform(promptFile.Platform, sourceFile.Platform) {
				decodedPrompt := decodePrompt(promptFile.Prompt, sourceFile.FilePath, sourceFile.Content)
				prompts <- Prompt{
					SourceFile: sourceFile,
					PromptFile: promptFile,
					Prompt:     decodedPrompt,
					Platform:   promptFile.Platform,
				}
			}
		}
	}
	close(prompts)
}

func decodePrompt(p, filename, sourceContent string) string {
	keysToValues := make(map[string]string)
	keysToValues["file"] = filename
	p2 := replaceKeywordsWithValues(p, keysToValues)
	keysToValues = make(map[string]string)
	keysToValues["content"] = sourceContent // don't mix content with other keys since it may have ${..} patterns as well
	return replaceKeywordsWithValues(p2, keysToValues)

}

func replaceKeywordsWithValues(input string, keysToValues map[string]string) string {
	for key, value := range keysToValues {
		placeholder := "${" + key + "}"
		input = strings.ReplaceAll(input, placeholder, value)
	}

	return input
}
