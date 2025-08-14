package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

// 　JWKを作成してJSONにして返す
func MakeJWK() []byte {

	data, _ := os.ReadFile("jwt-public.pem")
	keyset, _ := jwk.ParseKey(data, jwk.WithPEM(true))

	keyset.Set(jwk.KeyIDKey, "12345678")
	keyset.Set(jwk.AlgorithmKey, "RS256")
	keyset.Set(jwk.KeyUsageKey, "sig")

	jwk := map[string][]jwk.Key{
		"keys": {keyset},
	}
	buf, _ := json.MarshalIndent(jwk, "", "  ")
	return buf
}

func (j *JWS) Make() (string, error) {
	HeaderJson, err := json.Marshal(j.Header)
	if err != nil {
		slog.Error("failed to marshal header", "error", err)
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(HeaderJson)
	payloadJson, err := json.Marshal(j.Payload)
	if err != nil {
		slog.Error("failed to marshal payload", "error", err)
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadBase64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadJson)

	signingInput := fmt.Sprintf("%s.%s", headerBase64, payloadBase64)

	var signatureBase64 string
	switch j.Header.Alg {
	case "RS256":
		signatureBase64, err = rs256(signingInput)
		if err != nil {
			slog.Error("failed to create RS256 signature", "error", err)
			return "", fmt.Errorf("failed to create RS256 signature: %w", err)
		}
	case "HS256":
		signatureBase64, err = hs256(j.Payload.Aud, signingInput)
		if err != nil {
			slog.Error("failed to create HS256 signature", "error", err)
			return "", fmt.Errorf("failed to create HS256 signature: %w", err)
		}
	default:
	}

	// Set the signature in the JWS struct
	j.Signature = signatureBase64
	return fmt.Sprintf("%s.%s", signingInput, signatureBase64), nil
}

func rs256(signingInput string) (string, error) {
	data, err := os.ReadFile("jwt-private.pem")
	if err != nil {
		slog.Error("failed to read private key file", "error", err)
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}
	block, _ := pem.Decode([]byte(data))
	if block == nil || block.Type != "PRIVATE KEY" {
		slog.Error("failed to decode PEM block", "error", "invalid PEM format")
		return "", fmt.Errorf("failed to decode PEM block: invalid PEM format")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		slog.Error("failed to parse private key", "error", err)
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}
	hasher := crypto.SHA256.New()
	_, err = hasher.Write([]byte(signingInput))
	if err != nil {
		slog.Error("failed to write to hasher", "error", err)
		return "", fmt.Errorf("failed to write to hasher: %w", err)
	}
	hashed := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, hashed)
	if err != nil {
		slog.Error("failed to sign data", "error", err)
		return "", fmt.Errorf("failed to sign data: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature), nil
}

func hs256(clientId, signingInput string) (string, error) {
	sharedSecret, err := os.ReadFile(fmt.Sprintf("hs256/%s.key", clientId))
	if err != nil {
		slog.Error("failed to read private key file", "error", err)
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}
	h := hmac.New(sha256.New, sharedSecret)
	h.Write([]byte(signingInput))
	signature := h.Sum(nil)

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature), nil
}

func (j *JWE) Make() (string, error) {
	return "", fmt.Errorf("JWE Make method not implemented")
}
