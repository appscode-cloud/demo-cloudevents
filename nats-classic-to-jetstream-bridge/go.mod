module github.com/appscodelabs/demo-cloudevents/nats/v2

go 1.24.0

require (
	github.com/cloudevents/sdk-go/protocol/nats/v2 v2.2.0
	github.com/cloudevents/sdk-go/v2 v2.2.0
	github.com/nats-io/jwt v1.0.1
	github.com/nats-io/nats-server/v2 v2.1.8-0.20200923205306-12d84c646c79
	github.com/nats-io/nats.go v1.10.1-0.20200606002146-fc6fed82929a
	github.com/nats-io/nkeys v0.2.0
	github.com/the-redback/go-oneliners v0.0.0-20190417084731-74f7694e6dae
)

require (
	github.com/fatih/color v1.9.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20190818114111-108c894c2c0e // indirect
	github.com/lightstep/tracecontext.go v0.0.0-20181129014701-1757c391b1ac // indirect
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.11 // indirect
	github.com/minio/highwayhash v1.0.0 // indirect
	github.com/nats-io/jwt/v2 v2.0.0-20200916203241-1f8ce17dff02 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	go.opencensus.io v0.22.0 // indirect
	go.uber.org/atomic v1.4.0 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.10.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	google.golang.org/protobuf v1.24.0 // indirect
)

replace github.com/nats-io/nats-server/v2 => github.com/masudur-rahman/nats-server/v2 v2.1.8-0.20200929110001-c8c48f43e224
