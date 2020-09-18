package main

import (
	"log"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"

	natsd "github.com/nats-io/nats-server/v2/server"
	server "github.com/nats-io/nats-streaming-server/server"
)

func main() {
	_, err := StartNATSServer()
	if err != nil {
		log.Fatal(err)
	}

	var done chan bool
	<-done
}

func StartNATSServer() (*server.StanServer, error) {
	opts := &natsd.Options{
		Host:       "localhost",
		Port:       4222,
		LogFile:    "/dev/stdout",
		Trace:      true,
		ConfigFile: confs.ServerConfigFile,
	}

	opts, err := natsd.ProcessConfigFile(opts.ConfigFile)
	if err != nil {
		return nil, err
	}

	srv, err := server.Run(server.GetDefaultOptions(), opts)
	if err != nil {
		return nil, err
	}

	return srv, nil
}
