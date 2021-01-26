package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"time"

	natsd "github.com/nats-io/nats-server/v2/server"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

var (
	oSeed = []byte("SOABRGE6JOE7POOXTQ2UYPCADQD776UTJIMQHZQE4TS6TKYFPN3RXHCBKE")
	oJwt  = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJhdWQiOiJPQ0xUUlVHS0xBNVVTRFlSTTNKV1pONEdUVUVHT0VHQzc1U1NQNFJRQkhQSlk2TU5KR0lEVlZIVSIsImV4cCI6MTkxODkwMjAwMCwianRpIjoiMlYyWEZMTlRaTVNVWVpKUksyUzJRVjVWWVEzVzVFQUI3T0hZM0pRTU5EWENFN1kzQVFOQSIsImlhdCI6MTYwMzM2OTIwMCwiaXNzIjoiT0NMVFJVR0tMQTVVU0RZUk0zSldaTjRHVFVFR09FR0M3NVNTUDRSUUJIUEpZNk1OSkdJRFZWSFUiLCJuYW1lIjoiS08iLCJuYmYiOjE2MDMzNjkyMDAsInN1YiI6Ik9DTFRSVUdLTEE1VVNEWVJNM0pXWk40R1RVRUdPRUdDNzVTU1A0UlFCSFBKWTZNTkpHSURWVkhVIiwibmF0cyI6eyJzaWduaW5nX2tleXMiOlsiT0NMVFJVR0tMQTVVU0RZUk0zSldaTjRHVFVFR09FR0M3NVNTUDRSUUJIUEpZNk1OSkdJRFZWSFUiXSwidHlwZSI6Im9wZXJhdG9yIiwidmVyc2lvbiI6Mn19.LWIGE00WEHSdIVusOzKBM_26r7usi_0vJj2tGQA_6U9FheGO5qqg50FZQ568e11O8NhnyLZ_9PA_rObTQ2DyDg"
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
	println("Configuration directory: ", confs.ConfDir, "\n")
	oKp, _, oSeed, oJwt, err := CreateOperator("KO")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(oSeed))
	if err := ioutil.WriteFile(confs.OpJwtPath, []byte(oJwt), 0666); err != nil {
		panic(err)
	}
	//return

	sKp, sPub, sJwt, err := CreateAccount("SYS", oKp)
	if err != nil {
		panic(err)
	}
	_, _, _, sCreds, err := CreateUser("sys", sKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(confs.SysCredFile, []byte(sCreds), 0666); err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(confs.ServerConfigFile, []byte(fmt.Sprintf(`//listen: -1
jetstream: {max_mem_store: 10Gb, max_file_store: 10Gb}
host: localhost
port: 5222
operator: %s
resolver: {
	type: full
	dir: %s
}
system_account: %s`, confs.OpJwtPath, confs.ConfDir, sPub)), 0666)
	if err != nil {
		panic(err)
	}

	aKp, aPub, aJwt, err := CreateAccount("Admin", oKp)
	if err != nil {
		panic(err)
	}

	_, _, _, aCreds, err := CreateUser("admin", aKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "admin.creds"), aCreds, 0666); err != nil {
		panic(err)
	}

	xKp, xPub, xJwt, err := CreateAccount("A", oKp)
	if err != nil {
		panic(err)
	}
	claim, err := jwt.DecodeAccountClaims(xJwt)
	if err != nil {
		panic(err)
	}
	claim.Exports = jwt.Exports{
		&jwt.Export{
			Name:    "Events",
			Subject: "Events",
			Type:    jwt.Stream,
		},
		&jwt.Export{
			Name:         "Notifications",
			Subject:      "Notifications",
			Type:         jwt.Service,
			TokenReq:     false,
			ResponseType: jwt.ResponseTypeStream,
		},
	}
	xJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "X.jwt"), []byte(xJwt), 0666); err != nil {
		panic(err)
	}
	_, _, _, xCreds, err := CreateUser("x", xKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "x.creds"), xCreds, 0666); err != nil {
		panic(err)
	}

	claim, err = jwt.DecodeAccountClaims(aJwt)
	if err != nil {
		panic(err)
	}
	claim.Imports = jwt.Imports{
		&jwt.Import{
			Name:    "Events",
			Subject: "Events",
			Account: xPub,
			To:      "user.x",
			Type:    jwt.Stream,
		},
		&jwt.Import{
			Name:    "Notifications",
			Subject: "user.x.Notifications",
			Account: xPub,
			To:      "Notifications",
			Type:    jwt.Service,
		},
	}
	aJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}

	s, err := StartJSServer()
	if err != nil {
		panic(err)
	}
	defer s.Shutdown()

	if err = s.AccountResolver().Store(sPub, sJwt); err != nil {
		panic(err)
	}
	if err = s.AccountResolver().Store(aPub, aJwt); err != nil {
		panic(err)
	}
	if err = s.AccountResolver().Store(xPub, xJwt); err != nil {
		panic(err)
	}
	log.Println("Everything is okay, I guess")
}

func StartJSServer() (*natsd.Server, error) {
	opts := &natsd.Options{
		ConfigFile: confs.ServerConfigFile,
	}

	err := opts.ProcessConfigFile(opts.ConfigFile)
	if err != nil {
		return nil, err
	}
	opts.Port = 1222

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

func CreateOperator(name string) (nkeys.KeyPair, string, []byte, string, error) {
	oKp, err := nkeys.CreateOperator()
	if err != nil {
		return nil, "", nil, "", err
	}
	oPub, err := oKp.PublicKey()
	if err != nil {
		return nil, "", nil, "", err
	}

	oSeed, err := oKp.Seed()
	if err != nil {
		return nil, "", nil, "", err
	}
	claim := jwt.OperatorClaims{
		ClaimsData: jwt.ClaimsData{
			Audience:  oPub,
			Expires:   time.Now().AddDate(10, 0, 0).Unix(),
			ID:        oPub,
			IssuedAt:  time.Now().Unix(),
			Issuer:    "Masudur Rahman",
			Name:      oPub,
			NotBefore: time.Now().Unix(),
			Subject:   oPub,
		},
		Operator: jwt.Operator{
			SigningKeys: jwt.StringList{oPub},
		},
	}
	//claim := jwt.NewOperatorClaims(oPub)
	claim.Name = name
	oJwt, err := claim.Encode(oKp)
	if err != nil {
		return nil, "", nil, "", err
	}

	return oKp, oPub, oSeed, oJwt, nil
}

func CreateAccount(name string, oKp nkeys.KeyPair) (nkeys.KeyPair, string, string, error) {
	aKp, err := nkeys.CreateAccount()
	if err != nil {
		return nil, "", "", err
	}
	aPub, err := aKp.PublicKey()
	if err != nil {
		return nil, "", "", err
	}

	claim := jwt.NewAccountClaims(aPub)
	claim.Name = name
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 4096 * 1024, DiskStorage: 8192 * 1024, Streams: 3, Consumer: 4}
	aJwt, err := claim.Encode(oKp)
	if err != nil {
		return nil, "", "", err
	}

	return aKp, aPub, aJwt, nil
}

func CreateUser(name string, aKp nkeys.KeyPair) (nkeys.KeyPair, string, string, []byte, error) {
	uKp, err := nkeys.CreateUser()
	if err != nil {
		return nil, "", "", nil, err
	}
	uSeed, err := uKp.Seed()
	if err != nil {
		return nil, "", "", nil, err
	}

	uPub, err := uKp.PublicKey()
	if err != nil {
		return nil, "", "", nil, err
	}

	uClaim := jwt.NewUserClaims(uPub)
	uClaim.Name = name

	uJwt, err := uClaim.Encode(aKp)
	if err != nil {
		return nil, "", "", nil, err
	}
	uCreds, err := jwt.FormatUserConfig(uJwt, uSeed)
	if err != nil {
		return nil, "", "", nil, err
	}

	return uKp, uPub, uJwt, uCreds, nil
}
