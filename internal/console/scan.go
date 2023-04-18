package console

import (
	_ "embed" // Embed kics CLI img and scan-flags
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Checkmarx/kics/internal/console/flags"
	consoleHelpers "github.com/Checkmarx/kics/internal/console/helpers"
	"github.com/Checkmarx/kics/internal/constants"
	sentryReport "github.com/Checkmarx/kics/internal/sentry"
	"github.com/Checkmarx/kics/pkg/engine/source"
	"github.com/Checkmarx/kics/pkg/gpt"
	"github.com/Checkmarx/kics/pkg/scan"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	//go:embed assets/kics-console
	banner string

	//go:embed assets/scan-flags.json
	scanFlagsListContent string
)

const (
	scanCommandStr = "scan"
	initError      = "initialization error - "
)

// NewScanCmd creates a new instance of the scan Command
func NewScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   scanCommandStr,
		Short: "Executes a scan analysis",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return preRun(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd)
		},
	}
}

func initScanCmd(scanCmd *cobra.Command) error {
	if err := flags.InitJSONFlags(
		scanCmd,
		scanFlagsListContent,
		false,
		source.ListSupportedPlatforms(),
		source.ListSupportedCloudProviders()); err != nil {
		return err
	}

	if err := scanCmd.MarkFlagRequired(flags.PathFlag); err != nil {
		sentryReport.ReportSentry(&sentryReport.Report{
			Message:  "Failed to add command required flags",
			Err:      err,
			Location: "func initScanCmd()",
		}, true)
		log.Err(err).Msg("Failed to add command required flags")
	}
	return nil
}

func run(cmd *cobra.Command) error {
	changedDefaultQueryPath := cmd.Flags().Lookup(flags.QueriesPath).Changed
	changedDefaultLibrariesPath := cmd.Flags().Lookup(flags.LibrariesPath).Changed
	if err := consoleHelpers.InitShouldIgnoreArg(flags.GetStrFlag(flags.IgnoreOnExitFlag)); err != nil {
		return err
	}
	if err := consoleHelpers.InitShouldFailArg(flags.GetMultiStrFlag(flags.FailOnFlag)); err != nil {
		return err
	}
	if flags.GetStrFlag(flags.OutputPathFlag) != "" {
		updateReportFormats()
		flags.SetStrFlag(flags.OutputNameFlag, filepath.Base(flags.GetStrFlag(flags.OutputNameFlag)))
		if filepath.Ext(flags.GetStrFlag(flags.OutputPathFlag)) != "" {
			flags.SetStrFlag(flags.OutputPathFlag, filepath.Join(flags.GetStrFlag(flags.OutputPathFlag), string(os.PathSeparator)))
		}
		if err := os.MkdirAll(flags.GetStrFlag(flags.OutputPathFlag), os.ModePerm); err != nil {
			return err
		}
	}
	if flags.GetStrFlag(flags.PayloadPathFlag) != "" && filepath.Dir(flags.GetStrFlag(flags.PayloadPathFlag)) != "." {
		if err := os.MkdirAll(filepath.Dir(flags.GetStrFlag(flags.PayloadPathFlag)), os.ModePerm); err != nil {
			return err
		}
	}
	gracefulShutdown()

	// save the scan parameters into the ScanParameters struct
	scanParams := getScanParameters(changedDefaultQueryPath, changedDefaultLibrariesPath)

	return executeScanOrGpt(scanParams)
}

func updateReportFormats() {
	for _, format := range flags.GetMultiStrFlag(flags.ReportFormatsFlag) {
		if strings.EqualFold(format, "all") {
			flags.SetMultiStrFlag(flags.ReportFormatsFlag, consoleHelpers.ListReportFormats())
			break
		}
	}
}

func getScanParameters(changedDefaultQueryPath, changedDefaultLibrariesPath bool) *scan.Parameters {
	scanParams := scan.Parameters{
		CloudProvider:               flags.GetMultiStrFlag(flags.CloudProviderFlag),
		DisableCISDesc:              flags.GetBoolFlag(flags.DisableCISDescFlag),
		DisableFullDesc:             flags.GetBoolFlag(flags.DisableFullDescFlag),
		ExcludeCategories:           flags.GetMultiStrFlag(flags.ExcludeCategoriesFlag),
		ExcludePaths:                flags.GetMultiStrFlag(flags.ExcludePathsFlag),
		ExcludeQueries:              flags.GetMultiStrFlag(flags.ExcludeQueriesFlag),
		ExcludeResults:              flags.GetMultiStrFlag(flags.ExcludeResultsFlag),
		ExcludeSeverities:           flags.GetMultiStrFlag(flags.ExcludeSeveritiesFlag),
		IncludeQueries:              flags.GetMultiStrFlag(flags.IncludeQueriesFlag),
		InputData:                   flags.GetStrFlag(flags.InputDataFlag),
		OutputName:                  flags.GetStrFlag(flags.OutputNameFlag),
		OutputPath:                  flags.GetStrFlag(flags.OutputPathFlag),
		Path:                        flags.GetMultiStrFlag(flags.PathFlag),
		PayloadPath:                 flags.GetStrFlag(flags.PayloadPathFlag),
		PreviewLines:                flags.GetIntFlag(flags.PreviewLinesFlag),
		QueriesPath:                 flags.GetMultiStrFlag(flags.QueriesPath),
		LibrariesPath:               flags.GetStrFlag(flags.LibrariesPath),
		ReportFormats:               flags.GetMultiStrFlag(flags.ReportFormatsFlag),
		Platform:                    flags.GetMultiStrFlag(flags.TypeFlag),
		QueryExecTimeout:            flags.GetIntFlag(flags.QueryExecTimeoutFlag),
		LineInfoPayload:             flags.GetBoolFlag(flags.LineInfoPayloadFlag),
		DisableSecrets:              flags.GetBoolFlag(flags.DisableSecretsFlag),
		SecretsRegexesPath:          flags.GetStrFlag(flags.SecretsRegexesPathFlag),
		ScanID:                      scanID,
		ChangedDefaultLibrariesPath: changedDefaultLibrariesPath,
		ChangedDefaultQueryPath:     changedDefaultQueryPath,
		BillOfMaterials:             flags.GetBoolFlag(flags.BomFlag),
		ExcludeGitIgnore:            flags.GetBoolFlag(flags.ExcludeGitIgnore),
		Gpt:                         flags.GetStrFlag(flags.GptFlag),
	}

	return &scanParams
}

func executeScanOrGpt(scanParams *scan.Parameters) error {
	if len(scanParams.Gpt) > 0 {
		return executeGpt(scanParams)
	} else {
		return executeScan(scanParams)
	}
}

func executeGpt(scanParams *scan.Parameters) error {
	split := strings.Split(scanParams.Gpt, ",")
	if len(split) != 3 {
		err := errors.Errorf("Invalid GPT parameters '%s'. Must be \"<openap-api-key>,<query-text>,<platform-type>\"", scanParams.Gpt)
		log.Err(err)
		return err
	}

	path := scanParams.Path[0]
	apiKey := split[0]
	query := split[1]
	platform := split[2]

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

	log.Debug().Msg("gpt.scan(). openai-api-key: '" + apiKey + "', query: '" + query + "', platfrom: '" + platform + "', path: '" + path + "'")

	prompt, err := GetPrompt(path, platform, query)
	if err != nil {
		log.Err(err)
		return err
	}

	response, err := gpt.CallGPT(apiKey, prompt)

	if err != nil {
		log.Err(err)
		return err
	}

	result := strings.TrimSpace(extractResult(response))

	writeResult(result, path)

	return nil
}

func executeScan(scanParams *scan.Parameters) error {
	log.Debug().Msg("console.scan()")

	for _, warn := range warnings {
		log.Warn().Msgf(warn)
	}

	console := newConsole()

	console.preScan()

	client, err := scan.NewClient(scanParams, console.ProBarBuilder, console.Printer)

	if err != nil {
		log.Err(err)
		return err
	}

	err = client.PerformScan(ctx)

	if err != nil {
		log.Err(err)
		return err
	}

	return nil
}

// gracefulShutdown catches signal interrupt and returns the appropriate exit code
func gracefulShutdown() {
	c := make(chan os.Signal)
	// This line should not be lint, since golangci-lint has an issue about it (https://github.com/golang/go/issues/45043)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM) //nolint
	showErrors := consoleHelpers.ShowError("errors")
	interruptCode := constants.SignalInterruptCode
	go func(showErrors bool, interruptCode int) {
		<-c
		if showErrors {
			os.Exit(interruptCode)
		}
	}(showErrors, interruptCode)
}
