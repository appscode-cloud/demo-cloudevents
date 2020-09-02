package main

import (
	"context"
	"log"

	"github.com/cloudevents/sdk-go/protocol/nats/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	natsio "github.com/nats-io/nats.go"
	"github.com/the-redback/go-oneliners"
)

func main() {
	con, err := nats.NewConsumer("nats://localhost:4222", "NEW", nats.NatsOptions(func(opts *natsio.Options) error {
		opts.User = "admin"
		opts.Password = "admin"
		return nil
	}), nats.WithPullConsumer("ORDERS"))
	if err != nil {
		panic(err)
	}
	defer con.Close(context.Background())

	client, err := cloudevents.NewClient(con)
	if err != nil {
		panic(err)
	}

	for {
		err := client.StartReceiver(context.Background(), process)
		if err != nil {
			log.Printf("failed to start nats receiver, #{%s}", err.Error())
		}
	}
}

type Example struct {
	Sequence int    `json:"id"`
	Message  string `json:"message"`
}

func process(ctx context.Context, event cloudevents.Event) error {
	//oneliners.PrettyJson(event)
	data := &Example{}
	if err := event.DataAs(data); err != nil {
		return err
	}
	oneliners.PrettyJson(data)

	return nil
}
