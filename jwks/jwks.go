package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

type JSONWebKeySet struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// BuildJsonWebKeySet builds JSON web key set from the public keys provided
func BuildJsonWebKeySet(publicKeyPaths []string) ([]byte, error) {
	var keys []jose.JSONWebKey
	for _, publicKeyPath := range publicKeyPaths {
		log.Print("Reading public key")
		publicKeyContent, err := ioutil.ReadFile(publicKeyPath)

		if err != nil {
			return nil, errors.Wrap(err, "failed to read public key")
		}

		block, _ := pem.Decode(publicKeyContent)
		if block == nil {
			return nil, errors.Wrap(err, "frror decoding PEM file")
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing key content")
		}

		var alg jose.SignatureAlgorithm
		switch publicKey.(type) {
		case *rsa.PublicKey:
			alg = jose.RS256
		default:
			return nil, errors.New("public key is not of type RSA")
		}

		kid, err := KeyIDFromPublicKey(publicKey)
		if err != nil {
			return nil, errors.New("Failed to fetch key ID from public key")
		}

		keys = append(keys, jose.JSONWebKey{
			Key:       publicKey,
			KeyID:     kid,
			Algorithm: string(alg),
			Use:       "sig",
		})
	}

	keySet, err := json.MarshalIndent(JSONWebKeySet{Keys: keys}, "", "    ")
	if err != nil {
		return nil, errors.New("JSON encoding of web key set failed")
	}

	return keySet, nil
}

// KeyIDFromPublicKey derives a key ID non-reversibly from a public key
// reference: https://github.com/kubernetes/kubernetes/blob/0f140bf1eeaf63c155f5eba1db8db9b5d52d5467/pkg/serviceaccount/jwt.go#L89-L111
func KeyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

func main() {
	// args are paths to public key files to be included in the resultant key set
	args := os.Args[1:]
	jwksBytes, _ := BuildJsonWebKeySet(args)
	// keyset is written to ./keys.json
	os.WriteFile("./keys.json", jwksBytes, 0644)
}
