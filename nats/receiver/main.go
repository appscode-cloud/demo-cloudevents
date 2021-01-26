package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
	natsio "github.com/nats-io/nats.go"

	"github.com/cloudevents/sdk-go/protocol/nats/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/the-redback/go-oneliners"
)

func main() {
	con, err := nats.NewConsumer("nats://localhost:5222", "ProcessEvents",
		nats.NatsOptions(natsio.UserCredentials(filepath.Join(confs.ConfDir, "admin.creds"))), nats.WithPullConsumer("ReceivedEvents"))
	if err != nil {
		panic(err)
	}
	defer con.Close(context.Background())
	log.Println("Jetstream receiver to `ProcessEvents` started...")

	client, err := cloudevents.NewClient(con)
	if err != nil {
		panic(err)
	}

	for {
		err := client.StartReceiver(context.Background(), processEvents)
		if err != nil {
			log.Printf("failed to start nats receiver, #{%s}", err.Error())
		}
	}
}

//type Example struct {
//	Sequence int    `json:"id"`
//	Message  string `json:"message"`
//}

func processEvents(ctx context.Context, event cloudevents.Event) error {
	var data = make(map[string]interface{})
	if err := event.DataAs(&data); err != nil {
		log.Println(err)
		return err
	}
	oneliners.PrettyJson(event.Subject())
	oneliners.PrettyJson(data)
	return nil

	//user := strings.Split(event.Subject(), ".")[1]
	//return SendNotificationToNatsServer(user+".Notifications", data)
}

func SendNotificationToNatsServer(subject string, data interface{}) error {
	sender, err := nats.NewSender("nats://localhost:4222", subject,
		nats.NatsOptions(natsio.UserCredentials("/home/masud/go/src/github.com/masudur-rahman/demo-cloudevents/nats-v2/confs/admin.creds")))
	if err != nil {
		return err
	}
	defer sender.Close(context.Background())
	client, err := cloudevents.NewClient(sender)
	if err != nil {
		return err
	}

	event := cloudevents.NewEvent()
	event.SetID("123-123-123")
	event.SetSubject(subject)
	event.SetType("com.demo-cloudevents.sent")
	event.SetTime(time.Now())
	event.SetSource("jetstream server")
	oneliners.PrettyJson(event, "Event before setting data")
	if err = event.SetData("application/json", data); err != nil {
		return err
	}
	oneliners.PrettyJson(event, "Newly created Event")
	oneliners.PrettyJson(data, "Message received from Consumer")

	result := client.Send(context.Background(), event)
	if cloudevents.IsUndelivered(result) {
		log.Printf("failed to send: %v", err)
		return err
	}
	log.Printf("Published message to %s channel...", "Events")
	log.Printf("sent: %d, accepted: %t", 1, cloudevents.IsACK(result))

	return nil
}
