package confs

import (
	"path/filepath"
	"runtime"
)

var (
	_, filePath, _, _ = runtime.Caller(0)
	ConfDir           = filepath.Dir(filePath)
	OpJwtPath         = filepath.Join(ConfDir, "KO.jwt")
	SysCredFile       = filepath.Join(ConfDir, "sys.creds")
	ServerConfigFile  = filepath.Join(ConfDir, "server.conf")
)
