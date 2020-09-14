package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/nats-io/jwt/v2"

	"github.com/nats-io/nats.go"

	natsd "github.com/nats-io/nats-server/v2/server"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"

	"github.com/nats-io/nkeys"
)

var (
	// This matches ./configs/nkeys_jwts/test.seed
	oSeed = []byte("SOAFYNORQLQFJYBYNUGC5D7SH2MXMUX5BFEWWGHN3EK4VGG5TPT5DZP7QU")
	// This matches ./configs/nkeys/op.jwt
	ojwt = "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJhdWQiOiJURVNUUyIsImV4cCI6MTg1OTEyMTI3NSwianRpIjoiWE5MWjZYWVBIVE1ESlFSTlFPSFVPSlFHV0NVN01JNVc1SlhDWk5YQllVS0VRVzY3STI1USIsImlhdCI6MTU0Mzc2MTI3NSwiaXNzIjoiT0NBVDMzTVRWVTJWVU9JTUdOR1VOWEo2NkFIMlJMU0RBRjNNVUJDWUFZNVFNSUw2NU5RTTZYUUciLCJuYW1lIjoiU3luYWRpYSBDb21tdW5pY2F0aW9ucyBJbmMuIiwibmJmIjoxNTQzNzYxMjc1LCJzdWIiOiJPQ0FUMzNNVFZVMlZVT0lNR05HVU5YSjY2QUgyUkxTREFGM01VQkNZQVk1UU1JTDY1TlFNNlhRRyIsInR5cGUiOiJvcGVyYXRvciIsIm5hdHMiOnsic2lnbmluZ19rZXlzIjpbIk9EU0tSN01ZRlFaNU1NQUo2RlBNRUVUQ1RFM1JJSE9GTFRZUEpSTUFWVk40T0xWMllZQU1IQ0FDIiwiT0RTS0FDU1JCV1A1MzdEWkRSVko2NTdKT0lHT1BPUTZLRzdUNEhONk9LNEY2SUVDR1hEQUhOUDIiLCJPRFNLSTM2TFpCNDRPWTVJVkNSNlA1MkZaSlpZTVlXWlZXTlVEVExFWjVUSzJQTjNPRU1SVEFCUiJdfX0.hyfz6E39BMUh0GLzovFfk3wT4OfualftjdJ_eYkLfPvu5tZubYQ_Pn9oFYGCV_6yKy3KMGhWGUCyCdHaPhalBw"
	oKp  nkeys.KeyPair
)

func init() {
	var err error
	oKp, err = nkeys.FromSeed(oSeed)
	if err != nil {
		panic(fmt.Sprintf("Parsing oSeed failed with: %v", err))
	}
}
func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	sysKp, _ := nkeys.CreateAccount()
	sysPub, _ := sysKp.PublicKey()
	//claim := jwt.NewAccountClaims(sysPub)
	//sysJwt, err := claim.Encode(oKp)
	//handleError(err)
	sysUKp, err := nkeys.CreateUser()
	handleError(err)
	sysUSeed, err := sysUKp.Seed()
	handleError(err)

	uclaim := jwt.NewUserClaims("test")
	uclaim.Subject, err = sysUKp.PublicKey()
	handleError(err)
	sysUserJwt, err := uclaim.Encode(sysKp)
	handleError(err)
	sysKp.Seed()
	sCreds, err := jwt.FormatUserConfig(sysUserJwt, sysUSeed)
	handleError(err)
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "test.creds"), []byte(sCreds), 0666); err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(confs.ServerConfigFile, []byte(fmt.Sprintf(` listen: -1
jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb}
operator: %s
resolver: {
	type: full
	dir: %s
}
system_account: %s
`, ojwt, confs.ConfDir, sysPub)), 0666)
	opts, err := natsd.ProcessConfigFile(confs.ServerConfigFile)
	handleError(err)
	s, err := natsd.NewServer(opts)
	handleError(err)
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		handleError(errors.New("nats server didn't start"))
	}
	defer s.Shutdown()
	_, err = nats.Connect(s.ClientURL(), nats.UserCredentials(filepath.Join(confs.ConfDir, "test.creds")))
	handleError(err)
	//updateJwt(s.ClientURL(), filepath.Join(confs.ConfDir, "test.creds"), sysPub, sysJwt)
}

const accUpdateEventSubj = "$SYS.ACCOUNT.%s.CLAIMS.UPDATE"

func updateJwt(url string, creds string, pubKey string, jwt string) {
	c, err := nats.Connect(url, nats.UserCredentials(creds))
	handleError(err)
	defer c.Close()
	if msg, err := c.Request(fmt.Sprintf(accUpdateEventSubj, pubKey), []byte(jwt), time.Second); err != nil {
		handleError(err)
	} else {
		content := make(map[string]interface{})
		if err := json.Unmarshal(msg.Data, &content); err != nil {
			handleError(err)
		} else if _, ok := content["data"]; !ok {
			handleError(nil)
		}
	}
}
