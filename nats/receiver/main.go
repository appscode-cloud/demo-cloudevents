package main

import (
	"context"
	"log"
	"path/filepath"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
	natsio "github.com/nats-io/nats.go"

	"github.com/cloudevents/sdk-go/protocol/nats/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/the-redback/go-oneliners"
)

func main() {
	con, err := nats.NewConsumer("nats://localhost:5222", "NEW",
		nats.NatsOptions(natsio.UserCredentials(filepath.Join(confs.ConfDir, "a.creds"))), nats.WithPullConsumer("ORDERS"))
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
	data := &Example{}
	if err := event.DataAs(data); err != nil {
		return err
	}
	oneliners.PrettyJson(data)

	//TODO: Send message to NATS/V2 server channel for user to listen

	return nil
}
