package gpt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	apiURL = "https://api.openai.com/v1/chat/completions"
)

type RequestBody struct {
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float32 `json:"temperature"`
	Model       string  `json:"model"`
}

type ResponseBody struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		Text         string      `json:"text"`
		Index        int         `json:"index"`
		Logprobs     interface{} `json:"logprobs"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		Prompt_tokens     int `json:"prompt_tokens"`
		Completion_tokens int `json:"completion_tokens"`
		Total_tokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type Result struct {
	QueryName   string `json:"queryName"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	Filename    string `json:"filename"`
	Description string `json:"description"`
}

func CallGPT(apiKey, prompt string) (string, error) {
	maxTokens := 2048

	requestBody := RequestBody{
		MaxTokens:   maxTokens,
		Model:       "gpt-4",
		Temperature: 0.0,
		Messages: []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			{Role: "user", Content: prompt},
		},
	}
	responseBody, err := callGPTAPI(apiKey, requestBody)

	if err != nil {
		log.Err(err)
		return "", err
	}
	return responseBody.Choices[0].Message.Content, nil
}

func callGPTAPI(apiKey string, requestBody RequestBody) (ResponseBody, error) {
	var responseBody ResponseBody

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return responseBody, err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return responseBody, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return responseBody, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return responseBody, err
	}

	if resp.StatusCode != http.StatusOK {
		return responseBody, fmt.Errorf("received non-200 status code: %d, response: %s", resp.StatusCode, string(body))
	}

	defer resp.Body.Close()

	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		return responseBody, err
	}

	return responseBody, nil
}

func ExtractResult(s string) []Result {
	jsonString := ExtractResultAsString(s)
	results, err := parseJSON(jsonString)
	if err != nil {
		return nil
	}
	return results
}

func ExtractResultAsString(s string) string {
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

func parseJSON(jsonString string) ([]Result, error) {
	var results []Result

	jsonString = changeLineToInt(jsonString)

	err := json.Unmarshal([]byte(jsonString), &results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func changeLineToInt(jsonString string) string {
	re := regexp.MustCompile(`"line":\s*("[^"]*"|\d+),`)
	matches := re.FindAllStringSubmatch(jsonString, -1)

	for _, match := range matches {
		val := strings.TrimSpace(match[1])
		if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
			val = val[1 : len(val)-1]
			intVal, err := strconv.Atoi(val)
			if err != nil {
				intVal = 0
			}
			jsonString = strings.Replace(jsonString, match[0], fmt.Sprintf("\"line\": %d,", intVal), 1)
		}
	}

	return jsonString
}
