package main

import (
	"errors"
	"log"
	"path/filepath"
	"time"

	"github.com/nats-io/jsm.go"
	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

func main() {
	//s, _, err := StartJSServer()
	//if err != nil {
	//	panic(err)
	//}
	//defer s.Shutdown()
	//fmt.Println(s.ClientURL())
	nc, err := nats.Connect("nats://localhost:5222", nats.UserCredentials(filepath.Join(confs.ConfDir, "admin.creds")))
	if err != nil {
		panic(err)
	}

	stream, err := AddStream("ReceivedEvents", "user.*.Events", nc)
	if err != nil {
		panic(err)
	}
	log.Printf("A stream named `%s` has been created", stream.Name())

	consumer, err := AddConsumer("ProcessEvents", "user.*.Events", stream.Name(), nc)
	if err != nil {
		panic(err)
	}
	log.Printf("A consumer named `%s` has been created", consumer.Name())

	//var done chan bool
	//<-done
}

func StartJSServer() (*natsd.Server, *nats.Conn, error) {
	opts := &natsd.Options{
		ConfigFile: confs.ServerConfigFile,
	}

	err := opts.ProcessConfigFile(opts.ConfigFile)
	if err != nil {
		return nil, nil, err
	}

	s, err := natsd.NewServer(opts)
	if err != nil {
		return nil, nil, err
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		return nil, nil, errors.New("nats server didn't start")
	}

	log.Println("NATS Server with Jetstream started...")

	nc, err := nats.Connect(s.ClientURL(), nats.UserCredentials(confs.SysCredFile))
	if err != nil {
		return nil, nil, err
	}
	log.Println("Connection to nats server established")

	return s, nc, nil
}

func AddStream(name, subject string, nc *nats.Conn) (*jsm.Stream, error) {
	stream, err := jsm.NewStreamFromDefault(name, jsm.DefaultWorkQueue, jsm.StreamConnection(
		jsm.WithConnection(nc)), jsm.Subjects(subject), jsm.FileStorage(), jsm.MaxAge(24*365*time.Hour),
		jsm.DiscardOld(), jsm.MaxMessages(-1), jsm.MaxBytes(-1), jsm.MaxMessageSize(512),
		jsm.DuplicateWindow(1*time.Hour))
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func AddConsumer(name, filter, stream string, nc *nats.Conn) (*jsm.Consumer, error) {
	consumer, err := jsm.NewConsumerFromDefault(stream, jsm.DefaultConsumer, jsm.ConsumerConnection(
		jsm.WithConnection(nc)), jsm.DurableName(name), jsm.MaxDeliveryAttempts(5),
		jsm.AckWait(30*time.Second), jsm.AcknowledgeExplicit(), jsm.ReplayInstantly(),
		jsm.DeliverAllAvailable(), jsm.FilterStreamBySubject(filter))
	if err != nil {
		return nil, err
	}

	return consumer, nil
}
