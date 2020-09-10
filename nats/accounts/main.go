package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func main() {
	oKp, _, _, _, err := CreateOperator("KO")
	if err != nil {
		panic(err)
	}
	aKp, _, _, err := CreateAccount("SYS", oKp)
	if err != nil {
		panic(err)
	}
	_, _, uJwt, uCreds, err := CreateUser("system_user", aKp)
	if err != nil {
		panic(err)
	}

	fmt.Println(uJwt, "\n\n", string(uCreds))
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
	claim := jwt.NewOperatorClaims(oPub)
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
