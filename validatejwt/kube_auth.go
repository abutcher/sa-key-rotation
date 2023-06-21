// https://stackoverflow.com/questions/51834234/i-have-a-public-key-and-a-jwt-how-do-i-check-if-its-valid-in-go
package main

import (
	"context"
	"errors"
	"fmt"
	"k8s.io/klog/v2"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

type privateClaims struct {
	Kubernetes kubernetes `json:"kubernetes.io,omitempty"`
}
type kubernetes struct {
	Namespace string           `json:"namespace,omitempty"`
	Svcacct   ref              `json:"serviceaccount,omitempty"`
	Pod       *ref             `json:"pod,omitempty"`
	Secret    *ref             `json:"secret,omitempty"`
	WarnAfter *jwt.NumericDate `json:"warnafter,omitempty"`
}

type ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// newServiceAccountAuthenticator returns an authenticator.Token or an error
func newServiceAccountAuthenticator(issuers []string, keyfiles []string, apiAudiences authenticator.Audiences) (authenticator.Token, error) {
	allPublicKeys := []interface{}{}
	for _, keyfile := range keyfiles {
		publicKeys, err := keyutil.PublicKeysFromFile(keyfile)
		if err != nil {
			return nil, err
		}
		allPublicKeys = append(allPublicKeys, publicKeys...)
	}

	tokenAuthenticator := serviceaccount.JWTTokenAuthenticator(issuers, allPublicKeys, apiAudiences, NewValidator())
	return tokenAuthenticator, nil
}

func NewValidator() serviceaccount.Validator {
	return &validator{}
}

type validator struct {
}

func (v *validator) Validate(ctx context.Context, _ string, public *jwt.Claims, privateObj interface{}) (*apiserverserviceaccount.ServiceAccountInfo, error) {
	private, ok := privateObj.(*privateClaims)
	if !ok {
		klog.Errorf("service account jwt validator expected private claim of type *privateClaims but got: %T", privateObj)
		return nil, errors.New("service account token claims could not be validated due to unexpected private claim")
	}
	nowTime := time.Now()
	err := public.Validate(jwt.Expected{
		Time: nowTime,
	})
	switch err {
	case nil:
		// successful validation

	case jwt.ErrExpired:
		return nil, errors.New("service account token has expired")

	case jwt.ErrNotValidYet:
		return nil, errors.New("service account token is not valid yet")

	case jwt.ErrIssuedInTheFuture:
		return nil, errors.New("service account token is issued in the future")

	// our current use of jwt.Expected above should make these cases impossible to hit
	case jwt.ErrInvalidAudience, jwt.ErrInvalidID, jwt.ErrInvalidIssuer, jwt.ErrInvalidSubject:
		klog.Errorf("service account token claim validation got unexpected validation failure: %v", err)
		return nil, fmt.Errorf("service account token claims could not be validated: %w", err) // safe to pass these errors back to the user

	default:
		klog.Errorf("service account token claim validation got unexpected error type: %T", err)                         // avoid leaking unexpected information into the logs
		return nil, errors.New("service account token claims could not be validated due to unexpected validation error") // return an opaque error
	}

	return &apiserverserviceaccount.ServiceAccountInfo{
		Namespace: private.Kubernetes.Namespace,
		Name:      private.Kubernetes.Svcacct.Name,
		UID:       private.Kubernetes.Svcacct.UID,
	}, nil
}

func (v *validator) NewPrivateClaims() interface{} {
	return &privateClaims{}
}
