package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/appscodelabs/demo-cloudevents/nats/v2/confs"
	"github.com/nats-io/jwt"
	natsd "github.com/nats-io/nats-server/v2/server"
)

func main2() {
	_, err := StartNATSServer()
	if err != nil {
		log.Fatal(err)
	}

	var done chan bool
	<-done
}

var (
	oSeed = []byte("SOABIGQTSJ52CEO2VWYUT73GJLNO3J2H7L6HVOOD6AFGKY35ZXG4QJFW7M")
	oJwt  = "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJhdWQiOiJPQ0NPS1NEQjVTWldaS1ZZSkxaM1ZNWFNMVUNRMlJaTVBDWVFPTENIQTU3WkJCVDNGQ0NCU0xQMyIsImV4cCI6MTYwMDg0MTU2MCwianRpIjoiNzJOQUNLR0dFNVhaRzZXWlpGSFhLTUNBWVFZN0k2U0JDREtPMkYzQkNYWUhTUldHVlRHUSIsImlhdCI6MTYwMDc1NTE2MCwiaXNzIjoiT0NDT0tTREI1U1pXWktWWUpMWjNWTVhTTFVDUTJSWk1QQ1lRT0xDSEE1N1pCQlQzRkNDQlNMUDMiLCJuYW1lIjoiS08iLCJuYmYiOjE2MDA3NTUxNjAsInN1YiI6Ik9DQ09LU0RCNVNaV1pLVllKTFozVk1YU0xVQ1EyUlpNUENZUU9MQ0hBNTdaQkJUM0ZDQ0JTTFAzIiwidHlwZSI6Im9wZXJhdG9yIiwibmF0cyI6eyJzaWduaW5nX2tleXMiOlsiT0NDT0tTREI1U1pXWktWWUpMWjNWTVhTTFVDUTJSWk1QQ1lRT0xDSEE1N1pCQlQzRkNDQlNMUDMiXX19.kCFsvOgD2omZmgnWAV1VeJTaZVnunOVQRxpK2IsqFWl2RY8CIVkekSp7PRIAobL5u8y2E1RBg8JLib4ddRk2Cw"
	oKp   nkeys.KeyPair
)

func init() {
	var err error
	oKp, err = nkeys.FromSeed(oSeed)
	if err != nil {
		panic(fmt.Sprintf("Parsing oSeed failed with: %v", err))
	}
}
func main() {
	//if Jwt, err := FetchAccount("ADOJV57ED3AMUGZEWSBIZCX6L55PXNOXXSABGOSHB6LOOE2S4PEVZ3PO"); err != nil {
	//	panic(err)
	//} else {
	//	fmt.Println(Jwt)
	//}
	if err := pushAccount(nil, filepath.Join(confs.ConfDir, "SYS.jwt")); err != nil {
		panic(err)
	}
	if err := pushAccount(nil, filepath.Join(confs.ConfDir, "admin.jwt")); err != nil {
		panic(err)
	}
	//if err := pushAccount(nil, filepath.Join(confs.ConfDir, "A.jwt")); err != nil {
	//	panic(err)
	//}
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
	fmt.Println("Subject: ", c.Subject)
	return ur.Store(c.Subject, string(data))
}

func FetchAccount(name string) (string, error) {
	ur, err := url.Parse("http://localhost:9090/jwt/v1/accounts/")
	if err != nil {
		return "", err
	}

	ur.Path = filepath.Join(ur.Path, name)

	resp, err := http.Get(ur.String())
	if err != nil {
		return "", fmt.Errorf("could not fetch <%q>: %v", ur.String(), err)
	} else if resp == nil {
		return "", fmt.Errorf("could not fetch <%q>: no response", ur.String())
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not fetch <%q>: %v", ur.String(), resp.Status)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
