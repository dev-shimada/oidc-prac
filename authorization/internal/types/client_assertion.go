package types

import (
	"encoding/base64"
	"net/http"
	"strings"
)

type ClientAssertionTypeNone struct{}
type ClientAssertionTypeClientSecretBasic struct {
	Secret string
}
type ClientAssertionTypeClientSecretPost struct{}
type ClientAssertionTypeClientSecretJwt struct{}
type ClientAssertionTypePrivateKeyJwt struct{}
type ClientAssertionTypeTlsClientAuth struct{}
type ClientAssertionTypeSelfSignedTlsClientAuth struct{}

func (c ClientAssertionTypeNone) Check(req http.Request) bool {
	return true
}
func (c ClientAssertionTypeClientSecretBasic) Check(req http.Request) bool {
	authorization := req.Header.Get("Authorization")
	encoded := strings.TrimPrefix(authorization, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}
	clientSecret := credentials[1]
	return clientSecret == c.Secret
}
func (c ClientAssertionTypeClientSecretPost) Check(req http.Request) bool {
	// TODO: Implement check logic for ClientSecretPost
	return false
}
func (c ClientAssertionTypeClientSecretJwt) Check(req http.Request) bool {
	// TODO: Implement check logic for ClientSecretJwt
	return false
}
func (c ClientAssertionTypePrivateKeyJwt) Check(req http.Request) bool {
	// TODO: Implement check logic for PrivateKeyJwt
	return false
}
func (c ClientAssertionTypeSelfSignedTlsClientAuth) Check(req http.Request) bool {
	// TODO: Implement check logic for SelfSignedTlsClientAuth
	return false
}
func (c ClientAssertionTypeTlsClientAuth) Check(req http.Request) bool {
	// TODO: Implement check logic for TlsClientAuth
	return false
}
