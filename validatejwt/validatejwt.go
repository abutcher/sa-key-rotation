// https://stackoverflow.com/questions/51834234/i-have-a-public-key-and-a-jwt-how-do-i-check-if-its-valid-in-go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	// Trim first arg, then args[0] is the token path and args[1] is the public key path
	args := os.Args[1:]

	tokenPath := args[0]
	publicKeyPath := args[1]

	isValid, err := verifyToken(tokenPath, publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	if isValid {
		fmt.Println("The token is valid")
	} else {
		fmt.Println("The token is invalid")
	}
}

func verifyToken(tokenPath, publicKeyPath string) (bool, error) {
	keyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return false, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return false, err
	}
	tokenData, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return false, err
	}

	realTokenAuthenticator, err := newServiceAccountAuthenticator(
		[]string{
			issuerFrom(string(tokenData)), // this effectively bypasses the issuer part
		},
		[]string{publicKeyPath},
		nil,
	)
	if err != nil {
		return false, err
	}
	response, ok, err := realTokenAuthenticator.AuthenticateToken(context.TODO(), string(tokenData))
	if ok {
		fmt.Printf("Kube says token is VALID\n\tUser:%v\n\tGroups:%v\n", response.User.GetName(), response.User.GetGroups())
		fmt.Printf("\nThe original code thinks: ")
	} else {
		fmt.Printf("Kube says token is NOT valid because %v\n", err)
		fmt.Printf("\nThe original code thinks: ")
	}

	token := string(tokenData)
	parts := strings.Split(token, ".")
	err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func issuerFrom(tokenData string) string {
	parts := strings.Split(tokenData, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	claims := struct {
		// WARNING: this JWT is not verified. Do not trust these claims.
		Issuer string `json:"iss"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	return claims.Issuer
}
