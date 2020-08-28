package main

import (
	"context"
	"log"
	"time"

	"github.com/cloudevents/sdk-go/protocol/nats/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	natsio "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/the-redback/go-oneliners"
)

type Example struct {
	Sequence int    `json:"id"`
	Message  string `json:"message"`
}

func main() {
	nKeySeed := "SUAO2CSEH5NABBK5ET33BH47E3PZECUKHCFTYNF45VLOVVDFSLCBCL3S3I"
	sender, err := nats.NewSender("nats://localhost:4222", "ORDERS.processed", nats.NatsOptions(func(opts *natsio.Options) error {
		opts.Nkey = "UDLDMAYR42UJ5UMBIVVC5ULD4IFQWHBNJEPIFWRMNVPKGR45H476I5SA"
		opts.SignatureCB = func(bytes []byte) ([]byte, error) {
			sk, err := nkeys.FromSeed([]byte(nKeySeed))
			if err != nil {
				return nil, err
			}
			return sk.Sign(bytes)
		}
		return nil
	}))
	if err != nil {
		panic(err)
	}
	defer sender.Close(context.Background())
	client, err := cloudevents.NewClient(sender)
	if err != nil {
		panic(err)
	}

	event := cloudevents.NewEvent()
	event.SetID("123-123-123")
	event.SetType("com.demo-cloudevents.sent")
	event.SetTime(time.Now())
	event.SetSource("demo-cloudevents/nats/sender")
	_ = event.SetData("application/json", &Example{
		Sequence: 1,
		Message:  "Hello, #application/json!",
	})

	oneliners.PrettyJson(event)

	if result := client.Send(context.Background(), event); cloudevents.IsUndelivered(result) {
		log.Printf("failed to send: %v", err)
	} else {
		log.Printf("sent: %d, accepted: %t", 1, cloudevents.IsACK(result))
	}
}
