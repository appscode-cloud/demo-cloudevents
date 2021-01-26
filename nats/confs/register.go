package confs

import (
	"path/filepath"

	demo_cloudevents "github.com/masudur-rahman/demo-cloudevents"
)

var (
	ConfDir          = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/ac_store")
	OpJwtPath        = filepath.Join(ConfDir, "KO.jwt")
	SysCredFile      = filepath.Join(ConfDir, "sys.creds")
	ServerConfigFile = filepath.Join(ConfDir, "server.conf")
)
