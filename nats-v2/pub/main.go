package main

import (
	"log"
	"path/filepath"

	"github.com/masudur-rahman/demo-cloudevents/nats/v2/confs"

	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Publisher"), nats.UserCredentials(filepath.Join(confs.ConfDir, "a.creds")))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	if err := nc.Publish("Notifications", []byte("Hello there...")); err != nil {
		log.Fatal(err)
	}

	/*conn, err := stan.Connect("test-cluster", "client", stan.NatsConn(nc))
	if err != nil {
		log.Fatal(err)
	}

	if err = conn.Publish("something", []byte("All is well")); err != nil {
		log.Fatal(err)
	}*/
}
