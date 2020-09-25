package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/masudur-rahman/demo-cloudevents/nats/v2/confs"
	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Publisher"), /*nats.UserCredentials(filepath.Join(confs.ConfDir, "a.creds")))*/
		nats.Token(fmt.Sprintf("_csrf %s", filepath.Join(confs.ConfDir, "a.creds"))))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	if err := nc.Publish("Events", []byte("Hello there...")); err != nil {
		log.Fatal(err)
	}
	log.Printf("Published message to %s channel...", "Events")
}
