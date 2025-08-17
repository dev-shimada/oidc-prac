package types

import (
	"encoding/base64"
	"strings"
)

type ClientAssertionTypeNone struct{}
type ClientAssertionTypeClientSecretBasic struct {
	Authorization string
}
type ClientAssertionTypeClientSecretPost struct{}
type ClientAssertionTypeClientSecretJwt struct{}
type ClientAssertionTypePrivateKeyJwt struct{}
type ClientAssertionTypeTlsClientAuth struct{}
type ClientAssertionTypeSelfSignedTlsClientAuth struct{}

func (c ClientAssertionTypeNone) Check(client Client) bool {
	return true
}
func (c ClientAssertionTypeClientSecretBasic) Check(client Client) bool {
	encoded := strings.TrimPrefix(c.Authorization, "Basic ")

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	clientID := credentials[0]
	clientSecret := credentials[1]

	// クライアント情報を確認
	if clientID != client.Id {
		return false
	}

	// シークレットを確認
	if clientSecret != client.Secret {
		return false
	}

	return true
}
func (c ClientAssertionTypeClientSecretPost) Check(client Client) bool {
	// TODO: Implement check logic for ClientSecretPost
	return false
}
func (c ClientAssertionTypeClientSecretJwt) Check(client Client) bool {
	// TODO: Implement check logic for ClientSecretJwt
	return false
}
func (c ClientAssertionTypePrivateKeyJwt) Check(client Client) bool {
	// TODO: Implement check logic for PrivateKeyJwt
	return false
}
func (c ClientAssertionTypeSelfSignedTlsClientAuth) Check(client Client) bool {
	// TODO: Implement check logic for SelfSignedTlsClientAuth
	return false
}
func (c ClientAssertionTypeTlsClientAuth) Check(client Client) bool {
	// TODO: Implement check logic for TlsClientAuth
	return false
}
