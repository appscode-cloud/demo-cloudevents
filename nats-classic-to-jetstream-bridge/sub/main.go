package main

import (
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"time"

	"github.com/appscodelabs/demo-cloudevents/nats/v2/confs"

	cnats "github.com/cloudevents/sdk-go/protocol/nats/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/nats-io/nats.go"
	"github.com/the-redback/go-oneliners"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Subscriber"), nats.UserCredentials(filepath.Join(confs.ConfDir, "admin.creds")))
	//nats.Token(fmt.Sprintf("_csrf %s", filepath.Join(confs.ConfDir, "admin.creds"))))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	subs, err := nc.Subscribe("*.Events", func(msg *nats.Msg) {
		log.Println(msg.Subject, "<==>", string(msg.Data))
		_ = SendMessageToJetStreamServer("user."+msg.Subject, msg.Data)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer subs.Unsubscribe()
	log.Printf("Subscribed to %s channel...", "*.Events")

	var done chan bool
	<-done
}

func SendMessageToJetStreamServer(subject string, msgByte []byte) error {
	sender, err := cnats.NewSender("nats://localhost:5222", subject,
		cnats.NatsOptions(nats.UserCredentials("/home/masud/go/src/github.com/appscodelabs/demo-cloudevents/nats/confs/admin.creds")))
	if err != nil {
		panic(err)
	}
	defer sender.Close(context.Background())
	client, err := cloudevents.NewClient(sender)
	if err != nil {
		panic(err)
	}

	var msg = make(map[string]interface{})
	if err = json.Unmarshal(msgByte, &msg); err != nil {
		return err
	}

	event := cloudevents.NewEvent()
	event.SetID("123-123-123")
	event.SetSubject(subject)
	event.SetType("com.demo-cloudevents.sent")
	event.SetTime(time.Now())
	event.SetSource("demo-cloudevents/nats/sender")
	_ = event.SetData("application/json", msg)

	oneliners.PrettyJson(event)

	if result := client.Send(context.Background(), event); cloudevents.IsUndelivered(result) {
		log.Printf("failed to send: %v", err)
	} else {
		log.Printf("sent: %d, accepted: %t", 1, cloudevents.IsACK(result))
	}
	log.Printf("Message sent to %s at %s using cred %s", subject, "nats://localhost:5222", "/home/masud/go/src/github.com/appscodelabs/demo-cloudevents/nats/confs/a.creds")
	return nil
}
