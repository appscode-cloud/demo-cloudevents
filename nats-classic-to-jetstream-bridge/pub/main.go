package main

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/appscodelabs/demo-cloudevents/nats/v2/confs"
	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Publisher"), nats.UserCredentials(filepath.Join(confs.ConfDir, "a.creds")))
	//nats.Token(fmt.Sprintf("_csrf %s", filepath.Join(confs.ConfDir, "a.creds"))))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	msg := map[string]string{
		"id":      "000000000000000",
		"message": "Hello there...",
	}
	data, err := json.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}

	if err := nc.Publish("Events", data); err != nil {
		log.Fatal(err)
	}
	log.Printf("Published message to %s channel...", "Events")
}
