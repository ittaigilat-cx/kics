package kics

import (
	"context"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"

	"github.com/Checkmarx/kics/pkg/model"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func (s *Service) sinkGpt(ctx context.Context, filename, scanID string, rc io.Reader, data []byte) error {
	s.Tracker.TrackFileFound()
	log.Debug().Msgf("Starting to process file '%s' with GPT", filename)

	c, err := getContent(rc, data)

	content := string(*c.Content)

	s.Tracker.TrackFileFoundCountLines(c.CountLines)

	if err != nil {
		return errors.Wrapf(err, "failed to get file content for file '%s'", filename)
	}

	platform := s.getPlatform(filename)

	file := model.FileMetadata{
		ID:           uuid.New().String(),
		ScanID:       scanID,
		OriginalData: content,
		Platform:     platform,
		FilePath:     filename,
		Content:      addLineNumbers(content),
	}

	s.saveToFile(ctx, &file)
	s.Tracker.TrackFileParse()
	log.Debug().Msgf("Finished processing file '%s'", filename)
	s.Tracker.TrackFileParseCountLines(c.CountLines)

	return errors.Wrap(err, "failed to save file content")
}

func (s *Service) getPlatform(filename string) string {
	fn := filepath.ToSlash(filename)
	for _, f := range s.GptInspector.GetFiles() {
		if filepath.ToSlash(f.File) == fn {
			return f.Type
		}
	}
	return "unknown"
}

func addLineNumbers(s string) string {
	lines := strings.Split(s, "\n")
	digits := int(math.Log10(math.Abs(float64(len(lines))))) + 1
	for i, line := range lines {
		lines[i] = fmt.Sprintf("[%*d] %s", digits, i+1, line)
	}
	return strings.Join(lines, "\n")
}
