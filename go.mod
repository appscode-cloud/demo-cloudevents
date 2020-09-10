module github.com/masudur-rahman/demo-cloudevents

go 1.14

require (
	github.com/cloudevents/sdk-go/protocol/nats/v2 v2.2.0
	github.com/cloudevents/sdk-go/v2 v2.2.0
	github.com/fatih/color v1.9.0 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20190818114111-108c894c2c0e // indirect
	github.com/nats-io/jsm.go v0.0.18
	github.com/nats-io/jwt v1.0.1 // indirect
	github.com/nats-io/jwt/v2 v2.0.0-20200827232814-292806fa48ba
	github.com/nats-io/nats-server/v2 v2.1.8-0.20200821234144-9bad6725aa10
	github.com/nats-io/nats.go v1.10.1-0.20200606002146-fc6fed82929a
	github.com/nats-io/nkeys v0.2.0
	github.com/the-redback/go-oneliners v0.0.0-20190417084731-74f7694e6dae
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a // indirect
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
)

replace (
	github.com/cloudevents/sdk-go/protocol/nats/v2 => github.com/tamalsaha/sdk-go/protocol/nats/v2 v2.2.1-0.20200831050400-1774999bfbb7
	github.com/nats-io/nats-server/v2 => ../../../github.com/nats-io/nats-server
)
