package confs

import (
	"path/filepath"

	demo_cloudevents "github.com/masudur-rahman/demo-cloudevents"
)

var (
	ConfDir      = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/ac_store")
	AccServerDir = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/nas_store")
	JSStoreDir   = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/jetstream")

	OpPubKey     = filepath.Join(ConfDir, "KO.pub")
	OperatorSeed = filepath.Join(ConfDir, "KO.nk")
	OpJwtPath    = filepath.Join(ConfDir, "KO.jwt")

	SYSAccountPubKey = filepath.Join(ConfDir, "SYS.pub")
	SYSAccountSeed   = filepath.Join(ConfDir, "SYS.nk")
	SYSAccountJwt    = filepath.Join(ConfDir, "SYS.jwt")
	SysCredFile      = filepath.Join(ConfDir, "sys.creds")

	AdminAccountPubKey = filepath.Join(ConfDir, "Admin.pub")
	AdminAccountSeed   = filepath.Join(ConfDir, "Admin.nk")
	AdminAccountJwt    = filepath.Join(ConfDir, "Admin.jwt")
	AdminCredFile      = filepath.Join(ConfDir, "admin.creds")

	XAccountPubKey = filepath.Join(ConfDir, "X.pub")
	XAccountSeed   = filepath.Join(ConfDir, "X.nk")
	XAccountJwt    = filepath.Join(ConfDir, "X.jwt")
	XCredFile      = filepath.Join(ConfDir, "x.creds")

	ServerConfigFile    = filepath.Join(ConfDir, "server.conf")
	AccountServerConfig = filepath.Join(ConfDir, "nas.conf")
)
