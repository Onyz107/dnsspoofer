//go:build !debug

package logger

import (
	"os"

	"github.com/charmbracelet/log"
)

var Logger = log.NewWithOptions(os.Stdout, log.Options{
	Level:           log.InfoLevel,
	ReportTimestamp: true,
})
