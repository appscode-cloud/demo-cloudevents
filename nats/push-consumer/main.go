package main

import (
	"errors"
	"fmt"
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
	nc, err := nats.Connect("nats://localhost:5222", nats.UserCredentials(filepath.Join(confs.ConfDir, "x.creds")))
	if err != nil {
		panic(err)
	}

	mgr, err := jsm.New(nc, jsm.WithTimeout(time.Second*2))
	if err != nil {
		panic(err)
	}

	stream, err := AddStream("Notifications", "x.Notifications", mgr)
	if err != nil {
		panic(err)
	}

	log.Printf("A stream named `%s` has been created", stream.Name())

	consumer, err := AddPushConsumer("Notifications", "x.Notifications", stream.Name(), mgr)
	if err != nil {
		panic(err)
	}

	log.Printf("A consumer named `%s` has been created", consumer.Name())

	adminnc, err := nats.Connect("nats://localhost:5222", nats.UserCredentials(filepath.Join(confs.ConfDir, "admin.creds")))
	if err != nil {
		panic(err)
	}
	go PublishMessage("user.x.Notifications", adminnc)

	// Populate pull consumer
	//fmt.Println("Populating pull consumer")
	//time.Sleep(4 * time.Second)

	ReadMessage("my.x.Notifications", nc)
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

func AddStream(name, subject string, mgr *jsm.Manager) (*jsm.Stream, error) {
	stream, err := mgr.LoadOrNewStreamFromDefault(name, jsm.DefaultWorkQueue,
		jsm.Subjects(subject), jsm.FileStorage(), jsm.MaxAge(24*365*time.Hour),
		jsm.DiscardOld(), jsm.MaxMessages(-1), jsm.MaxBytes(-1), jsm.MaxMessageSize(512),
		jsm.DuplicateWindow(1*time.Hour))
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func AddPushConsumer(name, filter, stream string, mgr *jsm.Manager) (*jsm.Consumer, error) {
	consumer, err := mgr.NewConsumerFromDefault(stream, jsm.DefaultConsumer,
		jsm.DurableName(name), jsm.MaxDeliveryAttempts(5), //jsm.AckWait(30*time.Second),
		jsm.AcknowledgeExplicit(), jsm.ReplayInstantly(), jsm.DeliverAllAvailable(),
		jsm.DeliverySubject("my."+filter), jsm.FilterStreamBySubject(filter))
	if err != nil {
		return nil, err
	}

	return consumer, nil
}

func ReadMessage(pushSubject string, nc *nats.Conn) {
	sc, err := nc.Subscribe(pushSubject, func(msg *nats.Msg) {
		fmt.Println(msg.Subject, "<==>", string(msg.Data))
		msg.Respond([]byte(""))
		//msg.Ack()
	})
	if err != nil {
		panic(err)
	}
	defer sc.Unsubscribe()

	var done chan bool
	<-done
}

func PublishMessage(subject string, nc *nats.Conn) {
	ticker := time.NewTicker(time.Second * 2)
	start := time.Now()

	for {
		select {
		case t := <-ticker.C:
			if err := nc.Publish(subject, []byte(fmt.Sprintf("Hello there, at %v", t.Format(time.RFC1123)))); err != nil {
			}

			if t.Sub(start).Seconds() > 10 {
				return
			}
		}
	}
}
