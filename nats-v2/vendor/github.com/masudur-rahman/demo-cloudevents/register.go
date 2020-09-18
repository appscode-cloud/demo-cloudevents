package demo_cloudevents

import (
	"path/filepath"
	"runtime"
)

var (
	_, filePath, _, _ = runtime.Caller(0)
	BaseDirectory     = filepath.Dir(filePath)
)
