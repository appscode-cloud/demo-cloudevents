package main

import (
	"errors"
	"log"
	"time"

	"github.com/the-redback/go-oneliners"

	"github.com/nats-io/jsm.go"
	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

func main() {
	_, nc, err := StartJSServer()
	if err != nil {
		panic(err)
	}
	defer nc.Close()

	//stream, err := AddStream("ORDERS", nc)
	//if err != nil {
	//	panic(err)
	//}
	//log.Printf("A stream named `%s` has been created", stream.Name())
	//
	//consumer, err := AddConsumer("NEW", "ORDERS.processed", stream.Name(), nc)
	//if err != nil {
	//	panic(err)
	//}
	//log.Printf("A consumer named `%s` has been created", consumer.Name())

	var done chan bool
	<-done
}

func StartJSServer() (*natsd.Server, *nats.Conn, error) {
	opts := &natsd.Options{
		JetStream:  true,
		StoreDir:   confs.ConfDir,
		Host:       "localhost",
		Port:       4222,
		LogFile:    "/dev/stdout",
		Trace:      true,
		ConfigFile: confs.ServerConfigFile,
	}

	opts, err := natsd.ProcessConfigFile(opts.ConfigFile)
	//err := opts.ProcessConfigFile(opts.ConfigFile)
	if err != nil {
		return nil, nil, err
	}
	oneliners.PrettyJson(opts, "opts")
	oneliners.PrettyJson(opts.Users, "Users")
	oneliners.PrettyJson(opts.Nkeys, "NKeys")
	oneliners.PrettyJson(opts.Accounts, "Accounts")
	oneliners.PrettyJson(opts.SystemAccount, "SystemAccount")
	oneliners.PrettyJson(opts.TrustedOperators, "TrustedOperators")
	//spew.Dump(opts.Accounts)
	s, err := natsd.NewServer(opts)
	if err != nil {
		return nil, nil, err
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		return nil, nil, errors.New("nats server didn't start")
	}

	log.Println("NATS Server with Jetstream started...")

	nc, err := nats.Connect(s.ClientURL(), nats.UserCredentials(confs.SysCredFile)) /*func(options *nats.Options) error {
		options.User = "admin"
		options.Password = "admin"
		return nil
	}*/
	if err != nil {
		return nil, nil, err
	}
	log.Println("Connection to nats server established")

	return s, nc, nil
}

func AddStream(name string, nc *nats.Conn) (*jsm.Stream, error) {
	stream, err := jsm.NewStreamFromDefault(name, jsm.DefaultWorkQueue, jsm.StreamConnection(
		jsm.WithConnection(nc)), jsm.Subjects(name+".*"), jsm.FileStorage(), jsm.MaxAge(24*365*time.Hour),
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
		//jsm.DeliverySubject("monitor.ORDERS"),
		jsm.DeliverAllAvailable(), jsm.FilterStreamBySubject(filter))
	if err != nil {
		return nil, err
	}

	return consumer, nil
}
