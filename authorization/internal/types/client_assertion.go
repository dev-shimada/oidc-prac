package types

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type ClientAssertionTypeNone struct{}
type ClientAssertionTypeClientSecretBasic struct {
	Secret string
}
type ClientAssertionTypeClientSecretPost struct {
	Secret string
}
type ClientAssertionTypeClientSecretJwt struct {
	Secret string
}
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
	clientSecret := req.PostFormValue("client_secret")
	if clientSecret == "" {
		return false
	}
	return clientSecret == c.Secret
}
func (c ClientAssertionTypeClientSecretJwt) Check(req http.Request) bool {
	clientAssertion := req.PostFormValue("client_assertion")
	if clientAssertion == "" {
		return false
	}

	clientAssertionType := req.PostFormValue("client_assertion_type")
	if clientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return false
	}

	parts := strings.Split(clientAssertion, ".")
	if len(parts) != 3 {
		return false
	}

	header, payload, signature := parts[0], parts[1], parts[2]

	// Verify signature
	signingInput := header + "." + payload
	expectedSignature := c.createHMACSignature(signingInput)
	if signature != expectedSignature {
		return false
	}

	// Decode and validate payload
	payloadBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payload)
	if err != nil {
		return false
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return false
	}

	// Validate required claims
	if !c.validateClaims(claims) {
		return false
	}

	return true
}

func (c ClientAssertionTypeClientSecretJwt) createHMACSignature(signingInput string) string {
	h := hmac.New(sha256.New, []byte(c.Secret))
	h.Write([]byte(signingInput))
	signature := h.Sum(nil)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature)
}

func (c ClientAssertionTypeClientSecretJwt) validateClaims(claims map[string]interface{}) bool {
	// Check required claims: iss, sub, aud, exp, iat
	iss, hasIss := claims["iss"].(string)
	sub, hasSub := claims["sub"].(string)
	_, hasAud := claims["aud"].(string)
	exp, hasExp := claims["exp"].(float64)
	iat, hasIat := claims["iat"].(float64)

	if !hasIss || !hasSub || !hasAud || !hasExp || !hasIat {
		return false
	}

	// iss and sub should be the same (client_id)
	if iss != sub {
		return false
	}

	// Check token expiration
	now := time.Now().Unix()
	if int64(exp) <= now {
		return false
	}

	// Check issued at time (not too far in the future)
	if int64(iat) > now+300 { // Allow 5 minute clock skew
		return false
	}

	return true
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
