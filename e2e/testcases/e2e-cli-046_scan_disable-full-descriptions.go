package testcases

import "regexp"

// E2E-CLI-046 - Kics scan command with --disable-telemetry
// should not fetch telemetry from environment URL KICS_DESCRIPTIONS_ENDPOINT.
func init() { //nolint
	testSample := TestCase{
		Name: "should not fetch telemetry from environment [E2E-CLI-046]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/positive.dockerfile",
					"-v",
					"--disable-telemetry"},
			},
		},
		Validation: func(outputText string) bool {
			uuidRegex := "Skipping all telemetry because provided disable flag is set"
			match, _ := regexp.MatchString(uuidRegex, outputText)
			return match
		},
		WantStatus: []int{50},
	}

	Tests = append(Tests, testSample)
}
