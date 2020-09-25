module github.com/masudur-rahman/demo-cloudevents/nats/v2

go 1.14

require (
	github.com/cloudevents/sdk-go/protocol/nats/v2 v2.2.0
	github.com/cloudevents/sdk-go/v2 v2.2.0
	github.com/nats-io/jwt v1.0.1
	github.com/nats-io/nats-server/v2 v2.1.8-0.20200923205306-12d84c646c79
	github.com/nats-io/nats.go v1.10.1-0.20200606002146-fc6fed82929a
	github.com/nats-io/nkeys v0.2.0
	github.com/the-redback/go-oneliners v0.0.0-20190417084731-74f7694e6dae
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a // indirect
	golang.org/x/sys v0.0.0-20200917073148-efd3b9a0ff20 // indirect
	google.golang.org/protobuf v1.24.0 // indirect
)

replace github.com/nats-io/nats-server/v2 => ../../../../github.com/nats-io/nats-server
