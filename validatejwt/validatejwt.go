// https://stackoverflow.com/questions/51834234/i-have-a-public-key-and-a-jwt-how-do-i-check-if-its-valid-in-go
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
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
	token := string(tokenData)
	parts := strings.Split(token, ".")
	err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return false, nil
	}
	return true, nil
}
