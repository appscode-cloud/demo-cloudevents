package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/masudur-rahman/demo-cloudevents/nats/v2/confs"

	"github.com/nats-io/nats.go"
)

func main() {
	nc, err := nats.Connect("localhost:4222", nats.Name("Message Subscriber"), /*nats.UserCredentials(filepath.Join(confs.ConfDir, "admin.creds")),*/
		nats.Token(fmt.Sprintf("_csrf %s", filepath.Join(confs.ConfDir, "admin.creds"))))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	subs, err := nc.Subscribe("*.Events", func(msg *nats.Msg) {
		log.Println(msg.Subject, "<==>", string(msg.Data))
	})
	if err != nil {
		log.Fatal(err)
	}
	defer subs.Unsubscribe()
	log.Printf("Subscribed to %s channel...", "*.Events")

	var done chan bool
	<-done
}
