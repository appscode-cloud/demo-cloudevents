package main

import (
	"errors"
	"log"
	"time"

	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func main() {
	_, nc, err := StartNATSServer()
	if err != nil {
		panic(err)
	}
	defer nc.Close()

	var done chan bool
	<-done
}

func StartNATSServer() (*natsd.Server, *nats.Conn, error) {
	opts := &natsd.Options{
		Host:    "localhost",
		Port:    4222,
		LogFile: "/dev/stdout",
		Trace:   true,
	}

	s, err := natsd.NewServer(opts)
	if err != nil {
		return nil, nil, err
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		return nil, nil, errors.New("nats server didn't start")
	}

	log.Println("NATS Server started...")

	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		return nil, nil, err
	}
	log.Println("Connection to nats server established")

	return s, nc, nil
}
