package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/masudur-rahman/demo-cloudevents/nats/server"

	jwtv1 "github.com/nats-io/jwt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/masudur-rahman/demo-cloudevents"
	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

var (
	oSeed = []byte("SOALXOSOXLRUB2O7YGXSPKRYRTANGHZ5IUWEZ7W3USHHMS42RPMCW4M5QI")
	oJwt  = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJhdWQiOiJPQ0ZJQ1FDQ0kySUFKTE1TVUpBSVJIWE9UQ0RNNkVPNElJRklPNFNQNVdTQjVUUUVHV1lNUzJWSyIsImV4cCI6MTYwMDE2NTAyNCwianRpIjoiWjcyNDJRU0c2VDZORjRBQVM0WkhNMzUyRzdJMldYQlpEM0xaRFNLS0kyT1I3NVlFTlBYQSIsImlhdCI6MTYwMDA3ODYyNCwiaXNzIjoiT0NGSUNRQ0NJMklBSkxNU1VKQUlSSFhPVENETTZFTzRJSUZJTzRTUDVXU0I1VFFFR1dZTVMyVksiLCJuYW1lIjoiS08iLCJuYmYiOjE2MDAwNzg2MjQsInN1YiI6Ik9DRklDUUNDSTJJQUpMTVNVSkFJUkhYT1RDRE02RU80SUlGSU80U1A1V1NCNVRRRUdXWU1TMlZLIiwibmF0cyI6eyJzaWduaW5nX2tleXMiOlsiT0NGSUNRQ0NJMklBSkxNU1VKQUlSSFhPVENETTZFTzRJSUZJTzRTUDVXU0I1VFFFR1dZTVMyVksiXSwidHlwZSI6Im9wZXJhdG9yIiwidmVyc2lvbiI6Mn19.vdQZj04L4Fq4CbF398mwpHtu0vUiDnaA5JiWe1h6xb99dhbO7LQcKAaw2k0LV0BJgYqnOP77cc-q1l6Wz4SJBg"
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
	println(demo_cloudevents.BaseDirectory, "\n")
	oKp, _, oSeed, oJwt, err := CreateOperatorV1("KO")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(oSeed))
	if err := ioutil.WriteFile(filepath.Join(confs.ConfDir, "KO.jwt"), []byte(oJwt), 0666); err != nil {
		panic(err)
	}
	return

	sKp, sPub, _, err := CreateAccount("SYS", oKp)
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
jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb}
host: localhost
port: 4222
operator: %s
//resolver: URL(http://localhost:9090/jwt/v1/accounts/)
resolver: {
	type: full
	dir: %s
}
system_account: %s`, filepath.Join(confs.ConfDir, "KO.jwt"), confs.ConfDir, sPub)), 0666)
	if err != nil {
		panic(err)
	}

	aKp, aPub, _, err := CreateAccount("A", oKp)
	if err != nil {
		panic(err)
	}
	claim := jwt.NewAccountClaims(aPub)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 4096 * 1024, DiskStorage: 8192 * 1024, Streams: 3, Consumer: 4}
	aJwt, err := claim.Encode(oKp)
	if err != nil {
		panic(err)
	}
	_, _, _, aCreds, err := CreateUser("a", aKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "a.creds"), aCreds, 0666); err != nil {
		panic(err)
	}

	bKp, bPub, _, err := CreateAccount("B", oKp)
	if err != nil {
		panic(err)
	}
	claim = jwt.NewAccountClaims(bPub)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 4096 * 1024, DiskStorage: 8192 * 1024, Streams: 3, Consumer: 4}
	bJwt, err := claim.Encode(oKp)
	if err != nil {
		panic(err)
	}
	_, _, _, bCreds, err := CreateUser("b", bKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "b.creds"), bCreds, 0666); err != nil {
		panic(err)
	}

	s, c, err := server.StartJSServer()
	if err != nil {
		panic(err)
	}
	defer c.Close()

	if msg, err := c.Request(fmt.Sprintf("$SYS.ACCOUNT.%s.CLAIMS.UPDATE", aPub), []byte(aJwt), 10*time.Second); err != nil {
		panic(err)
	} else {
		content := make(map[string]interface{})
		if err := json.Unmarshal(msg.Data, &content); err != nil {
			panic(err)
		} else if _, ok := content["data"]; !ok {
			panic(err)
		}
	}
	if msg, err := c.Request(fmt.Sprintf("$SYS.ACCOUNT.%s.CLAIMS.UPDATE", bPub), []byte(bJwt), 10*time.Second); err != nil {
		panic(err)
	} else {
		content := make(map[string]interface{})
		if err := json.Unmarshal(msg.Data, &content); err != nil {
			panic(err)
		} else if _, ok := content["data"]; !ok {
			panic(err)
		}
	}
	fmt.Println("Account jwt updated")
	fmt.Println(s.ClientURL())
	anc, err := nats.Connect(s.ClientURL(), nats.UserCredentials(filepath.Join(confs.ConfDir, "a.creds")), nats.ReconnectWait(200*time.Millisecond))
	if err != nil {
		panic(err)
	}
	//bnc, err := nats.Connect(s.ClientURL(), nats.UserCredentials(filepath.Join(confs.ConfDir, "b.creds")), nats.ReconnectWait(200*time.Millisecond))
	//if err != nil {
	//	panic(err)
	//}
	println("Connected")

	stream, err := server.AddStream("ORDERS", anc)
	if err != nil {
		panic(err)
	}
	log.Printf("A stream named `%s` has been created", stream.Name())

	consumer, err := server.AddConsumer("NEW", "ORDERS.processed", stream.Name(), anc)
	if err != nil {
		panic(err)
	}
	log.Printf("A consumer named `%s` has been created", consumer.Name())

	//fmt.Println(sJwt, "\n\n", string(sCreds))
	var done chan bool
	<-done
}

func CreateOperatorV1(name string) (nkeys.KeyPair, string, []byte, string, error) {
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
	claim := jwtv1.OperatorClaims{
		ClaimsData: jwtv1.ClaimsData{
			Audience:  oPub,
			Expires:   time.Now().Add(24 * time.Hour).Unix(),
			ID:        oPub,
			IssuedAt:  time.Now().Unix(),
			Issuer:    "Masudur Rahman",
			Name:      oPub,
			NotBefore: time.Now().Unix(),
			Subject:   oPub,
		},
		Operator: jwtv1.Operator{
			SigningKeys: jwtv1.StringList{oPub},
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
			Expires:   time.Now().Add(24 * time.Hour).Unix(),
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

func User() (*jwt.AccountClaims, error) {
	akp, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	//akp2, err := nkeys.CreateAccount()
	//if err != nil {
	//	return err
	//}

	apk, err := akp.PublicKey()
	if err != nil {
		return nil, err
	}
	//apk2, err := akp2.PublicKey()
	//if err != nil {
	//	return err
	//}

	activation := jwt.NewActivationClaims(apk)
	activation.Expires = time.Now().Add(time.Hour).UTC().Unix()

	account := jwt.NewAccountClaims(apk)
	if !account.Limits.IsUnlimited() {
		return nil, errors.New("expected unlimited operator limits")
	}
	account.Limits.Exports = 10
	account.Limits.WildcardExports = true

	account.Exports = jwt.Exports{}
	account.Exports.Add(&jwt.Export{
		Name:    "test export",
		Subject: "test.>",
		Type:    jwt.Stream,
	})

	return account, nil
}

func PushAccount(u string, data []byte) error {
	resp, err := http.Post(u, "application/jwt", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	//message, err := ioutil.ReadAll(resp.Body)
	return nil
}
