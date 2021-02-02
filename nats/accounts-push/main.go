package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

func main() {
	// Push system account information to account server
	sPub, err := ioutil.ReadFile(confs.SYSAccountPubKey)
	if err != nil {
		panic(err)
	}
	sJwt, err := ioutil.ReadFile(confs.SYSAccountJwt)
	if err != nil {
		panic(err)
	}
	if err := PushAccountToAccountServer(string(sPub), string(sJwt)); err != nil {
		panic(err)
	}

	// Push admin account information to account server
	aPub, err := ioutil.ReadFile(confs.AdminAccountPubKey)
	if err != nil {
		panic(err)
	}
	aJwt, err := ioutil.ReadFile(confs.AdminAccountJwt)
	if err != nil {
		panic(err)
	}
	if err := PushAccountToAccountServer(string(aPub), string(aJwt)); err != nil {
		panic(err)
	}

	// Push x account information to account server
	xPub, err := ioutil.ReadFile(confs.XAccountPubKey)
	if err != nil {
		panic(err)
	}
	xJwt, err := ioutil.ReadFile(confs.XAccountJwt)
	if err != nil {
		panic(err)
	}
	if err := PushAccountToAccountServer(string(xPub), string(xJwt)); err != nil {
		panic(err)
	}
}

func PushAccountToAccountServer(name, jwt string) error {
	ur, err := url.Parse("http://0.0.0.0:9090/jwt/v1/accounts/")
	if err != nil {
		return err
	}
	ur.Path = filepath.Join(ur.Path, name)
	resp, err := http.Post(ur.String(), "application/jwt", strings.NewReader(jwt))
	if err != nil {
		return err
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not post to <%q>: %v", ur.String(), resp.Status)
	}
	resp.Body.Close()

	return err
}
