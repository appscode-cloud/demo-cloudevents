package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/masudur-rahman/demo-cloudevents"
	"github.com/masudur-rahman/demo-cloudevents/nats/confs"
)

var (
	// This matches ./configs/nkeys_jwts/test.seed
	oSeed = []byte("SOAFYNORQLQFJYBYNUGC5D7SH2MXMUX5BFEWWGHN3EK4VGG5TPT5DZP7QU")
	// This matches ./configs/nkeys/op.jwt
	oJwt = "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJhdWQiOiJURVNUUyIsImV4cCI6MTg1OTEyMTI3NSwianRpIjoiWE5MWjZYWVBIVE1ESlFSTlFPSFVPSlFHV0NVN01JNVc1SlhDWk5YQllVS0VRVzY3STI1USIsImlhdCI6MTU0Mzc2MTI3NSwiaXNzIjoiT0NBVDMzTVRWVTJWVU9JTUdOR1VOWEo2NkFIMlJMU0RBRjNNVUJDWUFZNVFNSUw2NU5RTTZYUUciLCJuYW1lIjoiU3luYWRpYSBDb21tdW5pY2F0aW9ucyBJbmMuIiwibmJmIjoxNTQzNzYxMjc1LCJzdWIiOiJPQ0FUMzNNVFZVMlZVT0lNR05HVU5YSjY2QUgyUkxTREFGM01VQkNZQVk1UU1JTDY1TlFNNlhRRyIsInR5cGUiOiJvcGVyYXRvciIsIm5hdHMiOnsic2lnbmluZ19rZXlzIjpbIk9EU0tSN01ZRlFaNU1NQUo2RlBNRUVUQ1RFM1JJSE9GTFRZUEpSTUFWVk40T0xWMllZQU1IQ0FDIiwiT0RTS0FDU1JCV1A1MzdEWkRSVko2NTdKT0lHT1BPUTZLRzdUNEhONk9LNEY2SUVDR1hEQUhOUDIiLCJPRFNLSTM2TFpCNDRPWTVJVkNSNlA1MkZaSlpZTVlXWlZXTlVEVExFWjVUSzJQTjNPRU1SVEFCUiJdfX0.hyfz6E39BMUh0GLzovFfk3wT4OfualftjdJ_eYkLfPvu5tZubYQ_Pn9oFYGCV_6yKy3KMGhWGUCyCdHaPhalBw"
	oKp  nkeys.KeyPair
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
	//oKp, _, _, oJwt, err := CreateOperator("KO")
	//if err != nil {
	//	panic(err)
	//}
	sKp, _, _, err := CreateAccount("SYS", oKp)
	if err != nil {
		panic(err)
	}
	_, sPub, sJwt, sCreds, err := CreateUser("system_user", sKp)
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(confs.SysCredFile, []byte(sCreds), 0666); err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(confs.ServerConfigFile, []byte(fmt.Sprintf(`listen: -1
jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb}
operator: %s
resolver: {
	type: full
	dir: %s
}
system_account: %s`, oJwt, confs.ConfDir, sPub)), 0666)
	if err != nil {
		panic(err)
	}

	fmt.Println(sJwt, "\n\n", string(sCreds))
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
