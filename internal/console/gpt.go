package console

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	REGO_CODE_DELIMITER = "```\n"
	RESULT_FILE_NAME    = "gpt-result.json"
)

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
in the following %s code (taken from file %s), are there any security issues of type "%s" (this is the QUERY_NAME)? 
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
	return string(data), nil
}
