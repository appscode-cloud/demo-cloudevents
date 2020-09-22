package main

import (
	"log"
	"path/filepath"

	"github.com/masudur-rahman/demo-cloudevents/nats/v2/confs"

	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Publisher"), nats.UserCredentials(filepath.Join(confs.ConfDir, "b.creds")))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	subs, err := nc.Subscribe("a.Notifications", func(msg *nats.Msg) {
		log.Println(msg.Subject, "<==>", string(msg.Data))
	})
	if err != nil {
		log.Fatal(err)
	}
	defer subs.Unsubscribe()

	/*conn, err := stan.Connect("test-cluster", "client-2", stan.NatsConn(nc))
	if err != nil {
		log.Fatal(err)
	}

	sub, err := conn.Subscribe("something", func(msg *stan.Msg) {
		log.Println("Reply: ", string(msg.Data))
		msg.Ack()
	}, stan.SetManualAckMode(), stan.DurableName("i-remember"), stan.DeliverAllAvailable(), stan.AckWait(5*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer sub.Close()*/

	var done chan bool
	<-done
}
