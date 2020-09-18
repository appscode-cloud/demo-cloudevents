package main

import (
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Publisher"))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()
	conn, err := stan.Connect("test-cluster", "client-2", stan.NatsConn(nc))
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
	defer sub.Close()

	var done chan bool
	<-done
}
