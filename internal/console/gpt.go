package console

import (
	_ "embed" // Embed kics CLI img and scan-flags
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/Checkmarx/kics/internal/console/flags"
	sentryReport "github.com/Checkmarx/kics/internal/sentry"
	"github.com/Checkmarx/kics/pkg/engine/source"
	"github.com/Checkmarx/kics/pkg/gpt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	gptCommandStr       = "gpt"
	REGO_CODE_DELIMITER = "```\n"
	RESULT_FILE_NAME    = "gpt-result.json"
)

var (
	//go:embed assets/gpt-flags.json
	gptFlagsListContent string
)

// NewGptCmd creates a new instance of the scan Command
func NewGptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   gptCommandStr,
		Short: "Calls OpenAI GPT for querying vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGpt(cmd)
		},
	}
}

func initGptCmd(gptCmd *cobra.Command) error {
	if err := flags.InitJSONFlags(
		gptCmd,
		gptFlagsListContent,
		false,
		source.ListSupportedPlatforms(),
		source.ListSupportedCloudProviders()); err != nil {
		return err
	}

	if err := gptCmd.MarkFlagRequired(flags.GptPathFlag); err != nil {
		sentryReport.ReportSentry(&sentryReport.Report{
			Message:  "Failed to add command required flags",
			Err:      err,
			Location: "func initGptCmd()",
		}, true)
		log.Err(err).Msg("Failed to add command required flags")
	}
	return nil
}

func runGpt(cmd *cobra.Command) error {
	path := flags.GetStrFlag(flags.PathFlag)
	apiKey := flags.GetStrFlag(flags.ApiKey)
	query := flags.GetStrFlag(flags.QueryFlag)
	platform := flags.GetStrFlag(flags.PlatformFlag)

	fileInfo, err := os.Stat(path)
	if err != nil {
		err = errors.Wrap(err, "failed to open path")
		log.Err(err)
		return err
	}

	if fileInfo.IsDir() {
		err := errors.Errorf("Path '%s' is a directory. For now GPT expects a single file")
		log.Err(err)
		return err
	}

	msg := fmt.Sprintf("console.gpt(). openai-api-key: '%s', query: '%s', platfrom: '%s', path: '%s'", apiKey, query, platform, path)
	log.Info().Msg(msg) // TODO: change to Debug()

	prompt, err := GetPrompt(path, platform, query)
	if err != nil {
		log.Err(err)
		return err
	}
	fmt.Printf("<prompt>\n%s\n</prompt>\n", prompt)

	response, err := gpt.CallGPT(apiKey, prompt)

	fmt.Printf("<Response>\n%s\n</Response>\n", response)

	if err != nil {
		log.Err(err)
		return err
	}

	result := strings.TrimSpace(extractResult(response))

	fmt.Printf("<Result>\n%s\n</Result>\n", result)

	writeResult(result, path)

	return nil
}

func writeResult(result, path string) error {
	file := filepath.Join(filepath.Dir(path), RESULT_FILE_NAME)
	data := []byte(result)
	os.Remove(file)
	err := os.WriteFile(file, data, 0644)
	if err != nil {
		log.Err(err)
		return err
	}
	return nil
}

func extractResult(s string) string {
	var suffix, result string
	suffix = substringAfter(s, "REGO result file")
	result = substringAfter(suffix, "```")
	index := strings.Index(result, "```")
	if index != -1 {
		return result[:index]
	} else {
		return ""
	}
}

func substringAfter(s, k string) string {
	index := strings.Index(s, k)
	if index != -1 {
		return s[index+len(k):]
	} else {
		return ""
	}
}

func GetPrompt(path, platform, query string) (string, error) {
	content, err := ReadFileToString(path)
	if err != nil {
		err = errors.Errorf("Error reading %s: %s\n", path, err)
		log.Err(err)
		return "", err
	}
	file := filepath.Base(path)
	prompt := fmt.Sprintf(`
Explain the following %s code (taken from file %s), and check if there are any security issues of type "%s" (this is the QUERY_NAME)? 
If there are, in what lines of the code? Explain the issues that were found and then write them as a REGO result file.
%s
%s
%s
Use this format for the REGO result: 
%s
[
  {
    "queryName": <QUERY_NAME>,
    "severity": <SEVERITY>,
    "line": <the line in the code where the issue was found>,
    "filename": <FILE_NAME>
  }
]
%s
`, platform, file, query, REGO_CODE_DELIMITER, content, REGO_CODE_DELIMITER, REGO_CODE_DELIMITER, REGO_CODE_DELIMITER,
	)

	return prompt, nil
}

func ReadFileToString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	bare := string(data)

	return addLineNumbers(bare), nil
}

func addLineNumbers(s string) string {
	lines := strings.Split(s, "\n")
	digits := int(math.Log10(math.Abs(float64(len(lines))))) + 1
	for i, line := range lines {
		lines[i] = fmt.Sprintf("[%*d] %s", digits, i+1, line)
	}
	return strings.Join(lines, "\n")
}
