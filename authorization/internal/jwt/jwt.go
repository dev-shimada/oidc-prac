package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/dev-shimada/oidc-prac/authorization/internal/types"
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

type IdTokenMaker[T JWS] interface {
	Make(T) (string, error)
}
type JWS struct {
	Header    types.IdTokenHeader `json:"header"`
	Payload   types.JWT           `json:"payload"`
	Signature string              `json:"signature"`
}

func (j *JWS) Make() (string, error) {
	HeaderJson, _ := json.Marshal(j.Header)
	headerBase64 := base64.StdEncoding.EncodeToString(HeaderJson)
	payloadJson, _ := json.Marshal(j.Payload)
	payloadBase64 := base64.StdEncoding.EncodeToString(payloadJson)

	data, _ := os.ReadFile("jwt-private.pem")
	block, _ := pem.Decode([]byte(data))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	var alg crypto.Hash
	switch j.Header.Alg {
	case "RS256":
		alg = crypto.SHA256
	default:
	}
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, alg, []byte(fmt.Sprintf("%s.%s", headerBase64, payloadBase64)))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Set the signature in the JWS struct
	j.Signature = signatureBase64
	return fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signatureBase64), nil
}
