module github.com/appscodelabs/demo-cloudevents

go 1.23.0

require (
	github.com/cloudevents/sdk-go/protocol/nats/v2 v2.2.0
	github.com/cloudevents/sdk-go/v2 v2.2.0
	github.com/nats-io/jsm.go v0.0.23
	github.com/nats-io/jwt/v2 v2.7.3
	github.com/nats-io/nats-server/v2 v2.10.27
	github.com/nats-io/nats.go v1.39.1
	github.com/nats-io/nkeys v0.4.10
	github.com/the-redback/go-oneliners v0.0.0-20190417084731-74f7694e6dae
)

require (
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/fatih/color v1.9.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20190818114111-108c894c2c0e // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lightstep/tracecontext.go v0.0.0-20181129014701-1757c391b1ac // indirect
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.11 // indirect
	github.com/minio/highwayhash v1.0.3 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	go.opencensus.io v0.22.0 // indirect
	go.uber.org/atomic v1.4.0 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.10.0 // indirect
	golang.org/x/crypto v0.34.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/time v0.10.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

//replace github.com/cloudevents/sdk-go/protocol/nats/v2 => ../../../github.com/tamalsaha/sdk-go/protocol/nats/v2

replace github.com/cloudevents/sdk-go/protocol/nats/v2 => github.com/tamalsaha/sdk-go/protocol/nats/v2 v2.2.1-0.20210126105453-ecf7acedc0fe
