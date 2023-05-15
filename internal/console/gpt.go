package console

import (
	_ "embed" // Embed kics CLI img and scan-flags
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Checkmarx/kics/internal/console/flags"
	consoleHelpers "github.com/Checkmarx/kics/internal/console/helpers"
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
	RESULT_FILE_NAME    = "gpt-result"
	DETAILS_FILE_NAME   = "gpt-details"
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
	path := flags.GetStrFlag(flags.GptPathFlag)
	apiKey := flags.GetStrFlag(flags.ApiKey)
	query := flags.GetStrFlag(flags.QueryFlag)
	queryDetails := flags.GetStrFlag(flags.QueryDetailsFlag)
	platform := flags.GetStrFlag(flags.PlatformFlag)
	outputPath := flags.GetStrFlag(flags.GptOutputPathFlag)
	outputName := flags.GetStrFlag(flags.GptOutputNameFlag)
	if outputName == "" {
		outputName = RESULT_FILE_NAME
	}

	if outputPath == "" {
		outputPath = path
	}
	outputPath = filepath.Join(outputPath, outputName)

	isDir, err := consoleHelpers.IsPathDir(path)
	if err != nil {
		log.Err(err)
		return err
	}

	if isDir {
		err := errors.Errorf("Path '%s' is a directory. For now GPT expects a single file", path)
		log.Err(err)
		return err
	}

	msg := fmt.Sprintf("console.gpt(). openai-api-key: '%s', query: '%s', platfrom: '%s', input-path: '%s', output-path: '%s'", apiKey, query, platform, path, outputPath)

	log.Info().Msg(msg) // TODO: change to Debug()

	prompt, err := GetPrompt(path, platform, query, queryDetails)
	if err != nil {
		log.Err(err)
		return err
	}

	promptOutput := fmt.Sprintf("<prompt>\n%s\n</prompt>\n", prompt)
	fmt.Print(promptOutput)
	details := promptOutput

	response, err := gpt.CallGPT(apiKey, prompt)
	if err != nil {
		log.Err(err)
		return err
	}

	responseOutput := fmt.Sprintf("<Response>\n%s\n</Response>\n", response)
	fmt.Print(responseOutput)
	details += responseOutput

	result := strings.TrimSpace(extractResult(response))

	resultOutput := fmt.Sprintf("<Result>\n%s\n</Result>\n", result)
	fmt.Print(resultOutput)
	details += resultOutput

	if err := writeFile(result, outputPath+".json"); err != nil {
		return err
	}

	if flags.GetBoolFlag(flags.GptOutputDetailsFlag) {
		writeFile(details, outputPath+"-details.txt")
	}

	return nil
}

func writeFile(content, path string) error {
	data := []byte(content)
	os.Remove(path)
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		log.Err(err)
		return err
	}
	return nil
}

func extractResult(s string) string {
	var suffix, result string
	suffix = substringAfter(s, "REGO result")
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

func GetPrompt(path, platform, query, queryDetails string) (string, error) {
	content, err := ReadFileToStringWithLineNumbers(path)
	if err != nil {
		err = errors.Errorf("Error reading %s: %s\n", path, err)
		log.Err(err)
		return "", err
	}
	file := filepath.Base(path)

	prompt := GetPromptFromFile(query, file, platform, content)
	if prompt == "" {
		prompt = fmt.Sprintf(`
Explain the following %s code (taken from file %s), and check if there are any security issues of type "%s" (this is the QUERY_NAME) %s? 
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
`, platform, file, query, queryDetails, REGO_CODE_DELIMITER, content, REGO_CODE_DELIMITER, REGO_CODE_DELIMITER, REGO_CODE_DELIMITER,
		)
	}

	return prompt, nil
}

func GetPromptFromFile(query, file, platform, content string) string {
	p, err := ReadPromptFromFile(query)
	if err != nil {
		log.Err(err)
		return ""
	}
	keysToValues := make(map[string]string)
	keysToValues["file"] = file
	keysToValues["platform"] = platform
	p2 := ReplaceKeywordsWithValues(p, keysToValues)
	keysToValues = make(map[string]string)
	keysToValues["content"] = content // don't mix content with other keys since it may have ${..} patterns as well
	return ReplaceKeywordsWithValues(p2, keysToValues)
}

func ReadPromptFromFile(promptFile string) (string, error) {
	var basePath string
	log.Info().Msg(fmt.Sprintf("Trying to read prompt file '%s'", promptFile))
	p, err := ReadFileToString(promptFile)
	if err != nil {
		if basePath, err = consoleHelpers.GetSubDirPath("", flags.GetStrFlag(flags.GptPromptsPathFlag)); err != nil {
			return "", nil
		}
		promptFile = filepath.Join(basePath, promptFile)
		log.Info().Msg(fmt.Sprintf("Trying to read prompt file '%s'", promptFile))
		p, err = ReadFileToString(promptFile)
		if err != nil {
			return "", err
		}
	}

	kicsRegEx := regexp.MustCompile(`\$\{kics-([a-zA-Z]+)\}`)
	matches := kicsRegEx.FindAllStringSubmatch(p, -1)
	var values []string
	for _, match := range matches {
		values = append(values, match[1])
	}
	if len(values) == 0 {
		return p, nil
	}
	values = uniqueValues(values)
	templates, err := readTemplates(values)
	if err != nil {
		return "", err
	}
	log.Info().Msg(fmt.Sprintf("Found '%d' templates in prompt file '%s'", len(values), promptFile))
	p = ReplaceKeywordsWithValues(p, templates)
	return p, nil
}

func readTemplates(values []string) (map[string]string, error) {
	templates := make(map[string]string)
	for _, val := range values {
		templatesPath, err := consoleHelpers.GetSubDirPath("", flags.GetStrFlag(flags.GptTemplatesPathFlag))
		if err != nil {
			return templates, err
		}
		templateFilename := filepath.Join(templatesPath, val+".txt")
		log.Info().Msg(fmt.Sprintf("Trying to read template file '%s'", templateFilename))
		if template, err := ReadFileToString(templateFilename); err != nil {
			return templates, err
		} else {
			templates["kics-"+val] = template
		}
	}
	return templates, nil
}

func uniqueValues(values []string) []string {
	uniqueSet := make(map[string]bool)
	var uniqueSlice []string

	for _, val := range values {
		if _, exists := uniqueSet[val]; !exists {
			uniqueSet[val] = true
			uniqueSlice = append(uniqueSlice, val)
		}
	}
	return uniqueSlice
}

func ReplaceKeywordsWithValues(input string, keysToValues map[string]string) string {
	for key, value := range keysToValues {
		placeholder := "${" + key + "}"
		input = strings.ReplaceAll(input, placeholder, value)
	}

	return input
}

func ReadFileToString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	bare := string(data)
	return bare, nil
}

func ReadFileToStringWithLineNumbers(path string) (string, error) {
	bare, err := ReadFileToString(path)
	if err != nil {
		return "", err
	}
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
