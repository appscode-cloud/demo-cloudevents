module github.com/appscodelabs/demo-cloudevents

go 1.14

require (
	github.com/cloudevents/sdk-go/protocol/nats/v2 v2.2.0
	github.com/cloudevents/sdk-go/v2 v2.2.0
	github.com/fatih/color v1.9.0 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20190818114111-108c894c2c0e // indirect
	github.com/nats-io/jsm.go v0.0.23
	github.com/nats-io/jwt/v2 v2.0.2-0.20210423002137-22ab5427e625
	github.com/nats-io/nats-server/v2 v2.2.3-0.20210427005056-a67704e245a0
	github.com/nats-io/nats.go v1.10.1-0.20210428170450-aa4ab64c8ba0
	github.com/nats-io/nkeys v0.3.0
	github.com/the-redback/go-oneliners v0.0.0-20190417084731-74f7694e6dae
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
)

//replace github.com/cloudevents/sdk-go/protocol/nats/v2 => ../../../github.com/tamalsaha/sdk-go/protocol/nats/v2

replace github.com/cloudevents/sdk-go/protocol/nats/v2 => github.com/tamalsaha/sdk-go/protocol/nats/v2 v2.2.1-0.20210126105453-ecf7acedc0fe
