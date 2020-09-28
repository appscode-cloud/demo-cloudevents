package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/masudur-rahman/demo-cloudevents/nats/v2/confs"
	"github.com/nats-io/jwt"
	natsd "github.com/nats-io/nats-server/v2/server"
)

func main() {
	_, err := StartNATSServer()
	if err != nil {
		log.Fatal(err)
	}

	var done chan bool
	<-done
}

func StartNATSServer() (*natsd.Server, error) {
	if err := pushAccount(nil, filepath.Join(confs.ConfDir, "SYS.jwt")); err != nil {
		return nil, err
	}
	opts := &natsd.Options{
		Host:       "localhost",
		Port:       4222,
		LogFile:    "/dev/stdout",
		Trace:      true,
		ConfigFile: confs.ServerConfigFile,
		Websocket: natsd.WebsocketOpts{
			Port:       9222,
			NoTLS:      true,
			SameOrigin: false,
		},
	}

	err := opts.ProcessConfigFile(opts.ConfigFile)
	if err != nil {
		return nil, err
	}

	srv, err := natsd.NewServer(opts)
	if err != nil {
		return nil, err
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		return nil, errors.New("nats server didn't start")
	}

	if err := pushAccount(srv.AccountResolver(), filepath.Join(confs.ConfDir, "admin.jwt")); err != nil {
		return nil, err
	}
	if err := pushAccount(srv.AccountResolver(), filepath.Join(confs.ConfDir, "A.jwt")); err != nil {
		return nil, err
	}

	log.Printf("NATS Server 2.0 started at %s \n", srv.ClientURL())

	return srv, nil
}

func PushAccount(file string) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	c, err := jwt.DecodeAccountClaims(string(data))
	if err != nil {
		return err
	}
	u := url.URL{
		Scheme: "http",
		Host:   "localhost:9090",
		Path:   filepath.Join("/jwt/v1/accounts/", c.Subject),
	}
	resp, err := http.Post(u.String(), "application/jwt", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	//message, err := ioutil.ReadAll(resp.Body)
	return nil
}

func pushAccount(ur natsd.AccountResolver, file string) (err error) {
	if ur == nil {
		ur, err = natsd.NewURLAccResolver("http://localhost:9090/jwt/v1/accounts/")
		if err != nil {
			return
		}
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	c, err := jwt.DecodeAccountClaims(string(data))
	if err != nil {
		return err
	}
	return ur.Store(c.Subject, string(data))
}
