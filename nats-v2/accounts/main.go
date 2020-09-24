package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/masudur-rahman/demo-cloudevents/nats/v2/confs"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

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
	fmt.Println(confs.ConfDir)
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

	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "SYS.jwt"), []byte(sJwt), 0666); err != nil {
		panic(err)
	}
	_, _, _, sCreds, err := CreateUser("sys", sKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(confs.SysCredFile, []byte(sCreds), 0666); err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(confs.ServerConfigFile, []byte(fmt.Sprintf(`host: localhost
port: 2224
operator: %s
resolver: URL(http://localhost:9090/jwt/v1/accounts/)
system_account: %s`, confs.OpJwtPath, sPub)), 0666)
	if err != nil {
		panic(err)
	}

	aKp, aPub, aJwt, err := CreateAccount("A", oKp)
	if err != nil {
		panic(err)
	}
	claim, err := jwt.DecodeAccountClaims(aJwt)
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
	aJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "A.jwt"), []byte(aJwt), 0666); err != nil {
		panic(err)
	}
	_, _, _, aCreds, err := CreateUser("a", aKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "a.creds"), aCreds, 0666); err != nil {
		panic(err)
	}

	AKp, _, AJwt, err := CreateAccount("Admin", oKp)
	if err != nil {
		panic(err)
	}
	claim, err = jwt.DecodeAccountClaims(AJwt)
	if err != nil {
		panic(err)
	}

	claim.Imports = jwt.Imports{
		&jwt.Import{
			Name:    "Events",
			Subject: "Events",
			Account: aPub,
			To:      "a",
			Type:    jwt.Stream,
		},
		&jwt.Import{
			Name:    "Notifications",
			Subject: "Notifications",
			Account: aPub,
			To:      "a.Notifications",
			Type:    jwt.Service,
		},
	}
	AJwt, err = claim.Encode(oKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "admin.jwt"), []byte(AJwt), 0666); err != nil {
		panic(err)
	}
	_, _, _, ACreds, err := CreateUser("admin", AKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(filepath.Join(confs.ConfDir, "admin.creds"), ACreds, 0666); err != nil {
		panic(err)
	}

	log.Println("Everything is perfectly done, I guess...")
}

func CreateOperator(name string) (oKp nkeys.KeyPair, oPub string, oSeed []byte, oJwt string, err error) {
	oKp, err = nkeys.CreateOperator()
	if err != nil {
		return nil, "", nil, "", err
	}
	oPub, err = oKp.PublicKey()
	if err != nil {
		return nil, "", nil, "", err
	}

	oSeed, err = oKp.Seed()
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
	oJwt, err = claim.Encode(oKp)
	if err != nil {
		return nil, "", nil, "", err
	}

	return oKp, oPub, oSeed, oJwt, nil
}

func CreateAccount(name string, oKp nkeys.KeyPair) (aKp nkeys.KeyPair, aPub string, aJwt string, err error) {
	aKp, err = nkeys.CreateAccount()
	if err != nil {
		return nil, "", "", err
	}
	aPub, err = aKp.PublicKey()
	if err != nil {
		return nil, "", "", err
	}

	claim := jwt.NewAccountClaims(aPub)
	claim.Name = name
	aJwt, err = claim.Encode(oKp)
	if err != nil {
		return nil, "", "", err
	}

	return aKp, aPub, aJwt, nil
}

func CreateUser(name string, aKp nkeys.KeyPair) (uKp nkeys.KeyPair, uPub string, uJwt string, uCreds []byte, err error) {
	uKp, err = nkeys.CreateUser()
	if err != nil {
		return nil, "", "", nil, err
	}
	uSeed, err := uKp.Seed()
	if err != nil {
		return nil, "", "", nil, err
	}

	uPub, err = uKp.PublicKey()
	if err != nil {
		return nil, "", "", nil, err
	}

	uClaim := jwt.NewUserClaims(uPub)
	uClaim.Name = name

	uJwt, err = uClaim.Encode(aKp)
	if err != nil {
		return nil, "", "", nil, err
	}
	uCreds, err = jwt.FormatUserConfig(uJwt, uSeed)
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
