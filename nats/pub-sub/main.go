package main

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"time"

	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

func main() {
	s, err := StartJSServer()
	if err != nil {
		panic(err)
	}
	defer s.Shutdown()
	fmt.Println(s.ClientURL())

	go ReadMessage(s.ClientURL(), "x.creds", "Notifications")
	go ReadMessage(s.ClientURL(), "admin.creds", "user.x.Events")

	go PublishMessage(s.ClientURL(), "admin.creds", "user.x.Notifications")
	go PublishMessage(s.ClientURL(), "x.creds", "Events")

	var done chan bool
	<-done
}

func StartJSServer() (*natsd.Server, error) {
	opts := &natsd.Options{
		ConfigFile: confs.ServerConfigFile,
	}

	err := opts.ProcessConfigFile(opts.ConfigFile)
	if err != nil {
		return nil, err
	}

	s, err := natsd.NewServer(opts)
	if err != nil {
		return nil, err
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		return nil, errors.New("nats server didn't start")
	}

	log.Println("NATS Server with Jetstream started...")
	return s, nil
}

func ReadMessage(url, credFile, subject string) {
	nc, err := nats.Connect(url, nats.UserCredentials(filepath.Join(confs.ConfDir, credFile)))
	if err != nil {
		panic(err)
	}

	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		fmt.Printf("User: %s, Subject: %s\nMessage: %s\n\n", credFile, msg.Subject, string(msg.Data))
	})
	if err != nil {
		panic(err)
	}
	defer sub.Unsubscribe()

	var done chan bool
	<-done
}

func PublishMessage(url, credFile, subject string) {
	nc, err := nats.Connect(url, nats.UserCredentials(filepath.Join(confs.ConfDir, credFile)))
	if err != nil {
		panic(err)
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			if err := nc.Publish(subject, []byte(fmt.Sprintf("User: %s, Subject: %s", credFile, subject))); err != nil {
				panic(err)
			}
		}
	}
}
