package confs

import (
	"path/filepath"

	demo_cloudevents "github.com/masudur-rahman/demo-cloudevents"
)

var (
	ConfDir      = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/ac_store")
	AccServerDir = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/nas_store")
	JSStoreDir   = filepath.Join(demo_cloudevents.BaseDirectory, "nats/confs/jetstream")

	OperatorCreds = filepath.Join(ConfDir, "KO.creds")
	OpJwtPath     = filepath.Join(ConfDir, "KO.jwt")

	SYSAccountCreds = filepath.Join(ConfDir, "SYS_account.creds")
	SYSAccountJwt   = filepath.Join(ConfDir, "SYS.jwt")
	SysCredFile     = filepath.Join(ConfDir, "sys.creds")

	AdminAccountCreds = filepath.Join(ConfDir, "Admin_account.creds")
	AdminAccountJwt   = filepath.Join(ConfDir, "Admin.jwt")
	AdminCredFile     = filepath.Join(ConfDir, "admin.creds")

	XAccountCreds = filepath.Join(ConfDir, "X_account.creds")
	XAccountJwt   = filepath.Join(ConfDir, "X.jwt")
	XCredFile     = filepath.Join(ConfDir, "x.creds")

	YAccountCreds = filepath.Join(ConfDir, "Y_account.creds")
	YAccountJwt   = filepath.Join(ConfDir, "Y.jwt")
	YCredFile     = filepath.Join(ConfDir, "Y.creds")

	ServerConfigFile    = filepath.Join(ConfDir, "server.conf")
	AccountServerConfig = filepath.Join(ConfDir, "nas.conf")
)
