package main

import (
	"log"

	"github.com/nats-io/stan.go"

	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Publisher"))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	conn, err := stan.Connect("test-cluster", "client", stan.NatsConn(nc))
	if err != nil {
		log.Fatal(err)
	}

	if err = conn.Publish("something", []byte("All is well")); err != nil {
		log.Fatal(err)
	}
}
