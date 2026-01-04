package logger

import (
	"os"

	"github.com/charmbracelet/log"
)

var Log = log.NewWithOptions(os.Stdout, log.Options{
	Level:           log.InfoLevel,
	ReportTimestamp: true,
})
