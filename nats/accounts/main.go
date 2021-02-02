package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/masudur-rahman/demo-cloudevents/nats/confs"

	"github.com/nats-io/jwt/v2"
	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

func main() {
	println("Configuration directory: ", confs.ConfDir, "\n")
	if err := os.MkdirAll(confs.ConfDir, os.ModePerm); err != nil {
		panic(err)
	}

	oKp, oPub, oSeed, oJwt, err := CreateOperator("KO")
	if err != nil {
		panic(err)
	}

	sKp, sPub, sSeed, sJwt, err := CreateAccount("SYS", oKp)
	if err != nil {
		panic(err)
	}
	_, _, _, sCreds, err := CreateUser("sys", sKp)
	if err != nil {
		panic(err)
	}

	aKp, aPub, aSeed, aJwt, err := CreateAccount("Admin", oKp)
	if err != nil {
		panic(err)
	}
	_, _, _, aCreds, err := CreateUser("admin", aKp)
	if err != nil {
		panic(err)
	}

	xKp, xPub, xSeed, xJwt, err := CreateAccount("X", oKp)
	if err != nil {
		panic(err)
	}
	_, _, _, xCreds, err := CreateUser("x", xKp)
	if err != nil {
		panic(err)
	}

	// Add Export subjects to X account
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

	// Add Import subjects to Admin account from X account
	claim, err = jwt.DecodeAccountClaims(aJwt)
	if err != nil {
		panic(err)
	}
	claim.Imports = jwt.Imports{
		&jwt.Import{
			Name:    "Events",
			Subject: "Events",
			Account: xPub,
			//To:           "user.x",
			LocalSubject: "user.x.Events",
			Type:         jwt.Stream,
		},
		&jwt.Import{
			Name:    "Notifications",
			Subject: "Notifications",
			Account: xPub,
			//To:      "Notifications",
			LocalSubject: "user.x.Notifications",
			Type:         jwt.Service,
		},
	}
	aJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}

	// Store Operator information
	if err = StoreAccountInformation(oPub, confs.OpPubKey, oSeed, confs.OperatorSeed, oJwt, confs.OpJwtPath, nil, ""); err != nil {
		panic(err)
	}

	// Store System Account information
	if err = StoreAccountInformation(sPub, confs.SYSAccountPubKey, sSeed, confs.SYSAccountSeed, sJwt, confs.SYSAccountJwt, sCreds, confs.SysCredFile); err != nil {
		panic(err)
	}

	// Store Admin Account information
	if err = StoreAccountInformation(aPub, confs.AdminAccountPubKey, aSeed, confs.AdminAccountSeed, aJwt, confs.AdminAccountJwt, aCreds, confs.AdminCredFile); err != nil {
		panic(err)
	}

	// Store X Account information
	if err = StoreAccountInformation(xPub, confs.XAccountPubKey, xSeed, confs.XAccountSeed, xJwt, confs.XAccountJwt, xCreds, confs.XCredFile); err != nil {
		panic(err)
	}

	// Store Nats server and account server configuration
	if err = StoreServerConfiguration(sPub); err != nil {
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

func CreateAccount(name string, oKp nkeys.KeyPair) (nkeys.KeyPair, string, []byte, string, error) {
	aKp, err := nkeys.CreateAccount()
	if err != nil {
		return nil, "", nil, "", err
	}
	aPub, err := aKp.PublicKey()
	if err != nil {
		return nil, "", nil, "", err
	}
	aSeed, err := aKp.Seed()
	if err != nil {
		return nil, "", nil, "", err
	}
	claim := jwt.NewAccountClaims(aPub)
	claim.Name = name
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 4096 * 1024, DiskStorage: 8192 * 1024, Streams: 10, Consumer: 10}
	aJwt, err := claim.Encode(oKp)
	if err != nil {
		return nil, "", nil, "", err
	}

	return aKp, aPub, aSeed, aJwt, nil
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

func StoreAccountInformation(pub, pubPath string, seed []byte, seedPath, jwts, jwtPath string, creds []byte, credFile string) error {
	if err := ioutil.WriteFile(pubPath, []byte(pub), 0666); err != nil {
		return err
	}
	if err := ioutil.WriteFile(seedPath, seed, 0666); err != nil {
		return err
	}
	if err := ioutil.WriteFile(jwtPath, []byte(jwts), 0666); err != nil {
		return err
	}
	if creds != nil {
		if err := ioutil.WriteFile(credFile, creds, 0666); err != nil {
			return err

		}
	}

	return nil
}

func StoreServerConfiguration(sPub string) error {
	/*
		resolver_preload: {
			%s : "%s"
			%s : "%s"
			%s : "%s"
		}
	*/
	err := ioutil.WriteFile(confs.ServerConfigFile, []byte(fmt.Sprintf(`jetstream: {max_mem_store: 10Gb, max_file_store: 10Gb, store_dir: %s}
host: 0.0.0.0
port: 5222
operator: %s
resolver: URL(%s)
system_account: %s
websocket: {
	host: 0.0.0.0
 	port: 9222
 	no_tls: true
}
`, confs.JSStoreDir, confs.OpJwtPath, "http://0.0.0.0:9090/jwt/v1/accounts/", sPub)), 0666)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(confs.AccountServerConfig, []byte(fmt.Sprintf(`operatorjwtpath: %s
http {
    host: 0.0.0.0
    port: 9090
}
store {
    dir: %s,
    readonly: false,
    shard: true
}
nats: {
    servers: ["nats://0.0.0.0:5222"],
    usercredentials: %s
}
`, confs.OpJwtPath, confs.AccServerDir, confs.SysCredFile)), 0666)
	if err != nil {
		return err
	}

	return nil
}
