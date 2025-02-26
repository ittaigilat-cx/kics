package helpers

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Checkmarx/kics/internal/metrics"
	"github.com/Checkmarx/kics/pkg/progress"
	"github.com/Checkmarx/kics/pkg/report"
	"github.com/hashicorp/hcl"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

const divisor = float32(100000)

var reportGenerators = map[string]func(path, filename string, body interface{}) error{
	"json":        report.PrintJSONReport,
	"sarif":       report.PrintSarifReport,
	"html":        report.PrintHTMLReport,
	"glsast":      report.PrintGitlabSASTReport,
	"pdf":         report.PrintPdfReport,
	"sonarqube":   report.PrintSonarQubeReport,
	"cyclonedx":   report.PrintCycloneDxReport,
	"junit":       report.PrintJUnitReport,
	"asff":        report.PrintASFFReport,
	"csv":         report.PrintCSVReport,
	"codeclimate": report.PrintCodeClimateReport,
}

// CustomConsoleWriter creates an output to print log in a files
func CustomConsoleWriter(fileLogger *zerolog.ConsoleWriter) zerolog.ConsoleWriter {
	fileLogger.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}

	fileLogger.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("%s:", i)
	}

	fileLogger.FormatErrFieldName = func(i interface{}) string {
		return "ERROR:"
	}

	fileLogger.FormatFieldValue = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}

	return *fileLogger
}

// FileAnalyzer determines the type of extension in the passed config file by its content
func FileAnalyzer(path string) (string, error) {
	ostat, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	rc, err := io.ReadAll(ostat)
	if err != nil {
		return "", err
	}
	var temp map[string]interface{}

	// CxSAST query under review
	if err := json.Unmarshal(rc, &temp); err == nil {
		return "json", nil
	}

	// CxSAST query under review
	if err := yaml.Unmarshal(rc, &temp); err == nil {
		return "yaml", nil
	}

	// CxSAST query under review
	if _, err := toml.Decode(string(rc), &temp); err == nil {
		return "toml", nil
	}

	// CxSAST query under review
	if c, err := hcl.Parse(string(rc)); err == nil {
		if err = hcl.DecodeObject(&temp, c); err == nil {
			return "hcl", nil
		}
	}

	return "", errors.New("invalid configuration file format")
}

// GenerateReport execute each report function to generate report
func GenerateReport(path, filename string, body interface{}, formats []string, proBarBuilder progress.PbBuilder) error {
	log.Debug().Msgf("helpers.GenerateReport()")
	metrics.Metric.Start("generate_report")

	progressBar := proBarBuilder.BuildCircle("Generating Reports: ")

	var err error = nil
	go progressBar.Start()
	defer progressBar.Close()

	for _, format := range formats {
		format = strings.ToLower(format)
		if err = reportGenerators[format](path, filename, body); err != nil {
			log.Error().Msgf("Failed to generate %s report", format)
			break
		}
	}
	metrics.Metric.Stop()
	return err
}

// GetExecutableDirectory - returns the path to the directory containing KICS executable
func GetExecutableDirectory() string {
	log.Debug().Msg("helpers.GetExecutableDirectory()")
	path, err := os.Executable()
	if err != nil {
		log.Err(err)
	}
	return filepath.Dir(path)
}

// GetDefaultQueryPath - returns the default query path
func GetDefaultQueryPath(path, queriesPath string) (string, error) {
	log.Debug().Msg("helpers.GetDefaultQueryPath()")
	queriesPath, err := GetSubDirPath(path, queriesPath)
	if err != nil {
		return "", err
	}

	log.Debug().Msgf("Queries found in %s", queriesPath)
	return queriesPath, nil
}

// GetDefaultExperimentalPath returns the default Experimental path
func GetDefaultExperimentalPath(experimentalQueriesPath string) (string, error) {
	log.Debug().Msg("helpers.GetDefaultExperimentalPath()")
	experimentalQueriesFile, err := GetSubDirPath("", experimentalQueriesPath)
	if err != nil {
		return "", err
	}

	log.Debug().Msgf("Experimental Queries found in %s", experimentalQueriesFile)
	return experimentalQueriesFile, nil
}

// GetSubDirPath - returns the full path of 'subDir' found by searching it as a sub-directory from 'path' upwards
// if 'path' is empty, take the executable path
func GetSubDirPath(path, subDir string) (string, error) {
	var err error
	var basePath string
	if path == "" {
		path = GetExecutableDirectory()
	}
	basePath = path

	subDirPath := filepath.Join(basePath, subDir)
	isDir, err := IsPathDir(subDirPath)
	for err != nil && !isDir {
		parentPath := filepath.Dir(basePath)
		if basePath == parentPath {
			err = fmt.Errorf("'%s' directory not found as sub-directory anywhere above '%s'", subDir, path)
			break
		}
		basePath = parentPath
		subDirPath = filepath.Join(basePath, subDir)
		isDir, err = IsPathDir(subDirPath)
	}
	if err != nil {
		return "", err
	}
	if !isDir {
		return "", fmt.Errorf("'%s' path '%s' is not a directory", subDir, subDirPath)
	}
	return subDirPath, nil
}

// IsPathDir - is the given path a directory?
func IsPathDir(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if fileInfo.IsDir() {
		return true, nil
	} else {
		return false, nil
	}
}

// ListReportFormats return a slice with all supported report formats
func ListReportFormats() []string {
	supportedFormats := make([]string, 0, len(reportGenerators))
	for reportFormats := range reportGenerators {
		supportedFormats = append(supportedFormats, reportFormats)
	}
	sort.Strings(supportedFormats)
	return supportedFormats
}

// GetNumCPU return the number of cpus available
func GetNumCPU() float32 {
	// Check if application is running inside docker
	_, err := os.Stat("/.dockerenv")
	if err == nil {
		numCPU, err := getCPUFromQuotaUS()
		if err == nil {
			return numCPU
		}
		numCPU, err = getCPUFromCPUMax()
		if err == nil {
			return numCPU
		}
	}

	return float32(runtime.NumCPU())
}

func getCPUFromQuotaUS() (float32, error) {
	f, err := os.Open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	if err != nil {
		return -1, err
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Err(err).Msg("failed to close '/sys/fs/cgroup/cpu/cpu.cfs_quota_us'")
		}
	}()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		text := scanner.Text()
		cpus, err := strconv.Atoi(text)
		if err != nil {
			return float32(cpus) / divisor, err
		}

		if cpus != -1 {
			return float32(cpus) / divisor, nil
		}

		return float32(runtime.NumCPU()), nil
	}

	return float32(runtime.NumCPU()), nil
}

func getCPUFromCPUMax() (float32, error) {
	f, err := os.Open("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return -1, err
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Err(err).Msg("failed to close '/sys/fs/cgroup/cpu.max'")
		}
	}()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		text := scanner.Text()
		stringCpus := strings.Split(text, " ")[0]
		cpus, err := strconv.Atoi(stringCpus)
		if err != nil {
			return float32(cpus) / divisor, err
		}

		if cpus != -1 {
			return float32(cpus) / divisor, nil
		}

		return float32(runtime.NumCPU()), nil
	}

	return float32(runtime.NumCPU()), nil
}
