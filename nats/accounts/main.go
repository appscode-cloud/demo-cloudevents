package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/appscodelabs/demo-cloudevents/nats/confs"

	"github.com/nats-io/jwt/v2"
	natsd "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

func main() {
	flag.StringVar(&confs.ConfsDir, "confs", "", "entire configuration directory")
	flag.StringVar(&confs.AcServerDir, "ac", "", "account server directory")
	flag.StringVar(&confs.JsStoreDir, "js", "", "jetstream storage directory")
	flag.Parse()

	confs.UpdateCredentialPaths()

	println("Configuration directory: ", confs.ConfDir(), "\n")

	if err := os.MkdirAll(confs.ConfDir(), os.ModePerm); err != nil {
		panic(err)
	}

	oKp, _, oSeed, oJwt, err := CreateOperator("KO")
	if err != nil {
		panic(err)
	}

	sKp, sPub, sSeed, sJwt, err := CreateAccount("SYS", oKp)
	if err != nil {
		panic(err)
	}
	_, _, suSeed, suJwt, err := CreateUser("sys", sKp)
	if err != nil {
		panic(err)
	}

	aKp, _, aSeed, aJwt, err := CreateAccount("Admin", oKp)
	if err != nil {
		panic(err)
	}
	_, _, auSeed, auJwt, err := CreateUser("admin", aKp)
	if err != nil {
		panic(err)
	}

	xKp, xPub, xSeed, xJwt, err := CreateAccount("X", oKp)
	if err != nil {
		panic(err)
		println(xPub)
	}
	_, _, xuSeed, xuJwt, err := CreateUser("x", xKp)
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
			Name:    "x.Events",
			Subject: "x.Events",
			Type:    jwt.Stream,
		},
		&jwt.Export{
			Name:         "x.Notifications",
			Subject:      "x.Notifications",
			Type:         jwt.Service,
			TokenReq:     false,
			ResponseType: jwt.ResponseTypeStream,
		},
	}
	xJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}

	yKp, yPub, ySeed, yJwt, err := CreateAccount("Y", oKp)
	if err != nil {
		panic(err)
		println(yPub)
	}
	_, _, yuSeed, yuJwt, err := CreateUser("y", yKp)
	if err != nil {
		panic(err)
	}

	// Add Export subjects to X account
	claim, err = jwt.DecodeAccountClaims(yJwt)
	if err != nil {
		panic(err)
	}
	claim.Exports = jwt.Exports{
		&jwt.Export{
			Name:    "y.Events",
			Subject: "y.Events",
			Type:    jwt.Stream,
		},
		&jwt.Export{
			Name:         "y.Notifications",
			Subject:      "y.Notifications",
			Type:         jwt.Service,
			TokenReq:     false,
			ResponseType: jwt.ResponseTypeStream,
		},
	}
	yJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}

	// Add Import subjects to Admin account from X account
	claim, err = jwt.DecodeAccountClaims(aJwt)
	if err != nil {
		panic(err)
	}
	//claim.Imports = jwt.Imports{
	//	&jwt.Import{
	//		Name:    "x.Events",
	//		Subject: "x.Events",
	//		Account: xPub,
	//		//To:           "user.x",
	//		LocalSubject: "user.x.Events",
	//		Type:         jwt.Stream,
	//	},
	//	&jwt.Import{
	//		Name:    "x.Notifications",
	//		Subject: "x.Notifications",
	//		Account: xPub,
	//		//To:      "Notifications",
	//		LocalSubject: "user.x.Notifications",
	//		Type:         jwt.Service,
	//	},
	//	&jwt.Import{
	//		Name:    "y.Events",
	//		Subject: "y.Events",
	//		Account: yPub,
	//		//To:           "user.x",
	//		LocalSubject: "user.y.Events",
	//		Type:         jwt.Stream,
	//	},
	//	&jwt.Import{
	//		Name:    "y.Notifications",
	//		Subject: "y.Notifications",
	//		Account: yPub,
	//		//To:      "Notifications",
	//		LocalSubject: "user.y.Notifications",
	//		Type:         jwt.Service,
	//	},
	//}
	aJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}

	// Store Operator information
	if err = StoreAccountInformation(oJwt, oSeed, confs.OperatorCreds, confs.OpJwtPath); err != nil {
		panic(err)
	}

	// Store System Account information

	if err := ioutil.WriteFile(filepath.Join(confs.ConfDir(), "SYS.pub"), []byte(sPub), 0666); err != nil {
		panic(err)
	}
	if err = StoreAccountInformation(sJwt, sSeed, confs.SYSAccountCreds, confs.SYSAccountJwt); err != nil {
		panic(err)
	}
	if err = StoreAccountInformation(suJwt, suSeed, confs.SysCredFile, ""); err != nil {
		panic(err)
	}

	// Store X Account information
	if err = StoreAccountInformation(xJwt, xSeed, confs.XAccountCreds, confs.XAccountJwt); err != nil {
		panic(err)
	}
	if err = StoreAccountInformation(xuJwt, xuSeed, confs.XCredFile, ""); err != nil {
		panic(err)
	}

	// Store Y Account information
	if err = StoreAccountInformation(yJwt, ySeed, confs.YAccountCreds, confs.YAccountJwt); err != nil {
		panic(err)
	}
	if err = StoreAccountInformation(yuJwt, yuSeed, confs.YCredFile, ""); err != nil {
		panic(err)
	}

	// Store Admin Account information
	if err = StoreAccountInformation(aJwt, aSeed, confs.AdminAccountCreds, confs.AdminAccountJwt); err != nil {
		panic(err)
	}
	if err = StoreAccountInformation(auJwt, auSeed, confs.AdminCredFile, ""); err != nil {
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
	if name != "SYS" {
		claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1}
	}
	aJwt, err := claim.Encode(oKp)
	if err != nil {
		return nil, "", nil, "", err
	}

	return aKp, aPub, aSeed, aJwt, nil
}

func CreateUser(name string, aKp nkeys.KeyPair) (nkeys.KeyPair, string, []byte, string, error) {
	uKp, err := nkeys.CreateUser()
	if err != nil {
		return nil, "", nil, "", err
	}
	uSeed, err := uKp.Seed()
	if err != nil {
		return nil, "", nil, "", err
	}

	uPub, err := uKp.PublicKey()
	if err != nil {
		return nil, "", nil, "", err
	}

	uClaim := jwt.NewUserClaims(uPub)
	uClaim.Name = name

	uJwt, err := uClaim.Encode(aKp)
	if err != nil {
		return nil, "", nil, "", err
	}

	return uKp, uPub, uSeed, uJwt, nil
}

func StoreAccountInformation(jwts string, seed []byte, credFile, jwtFile string) error {
	creds, err := FormatCredentialConfig(jwts, seed)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(credFile, creds, 0666); err != nil {
		return err
	}

	if len(jwtFile) > 0 {
		if err := ioutil.WriteFile(jwtFile, []byte(jwts), 0666); err != nil {
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
`, confs.JSStoreDir, confs.OpJwtPath, "http://localhost:9090/jwt/v1/accounts/", sPub)), 0666)
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
    servers: ["nats://localhost:5222"],
    usercredentials: %s
}
`, confs.OpJwtPath, confs.AccServerDir, confs.SysCredFile)), 0666)
	if err != nil {
		return err
	}

	return nil
}

// FormatCredentialConfig returns a decorated file with a decorated JWT and decorated seed
func FormatCredentialConfig(jwtString string, seed []byte) ([]byte, error) {
	w := bytes.NewBuffer(nil)
	jd, err := jwt.DecorateJWT(jwtString)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(jd)
	if err != nil {
		return nil, err
	}

	d, err := jwt.DecorateSeed(seed)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(d)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}
