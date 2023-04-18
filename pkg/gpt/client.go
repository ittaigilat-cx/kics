package gpt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

func CallGPT(apiKey, prompt string) (string, error) {
	maxTokens := 1750

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
