package types

import (
	"time"

	"github.com/dev-shimada/oidc-prac/authorization/internal/client_assertion"
)

type Session struct {
	Client                string
	State                 string
	Scopes                string
	RedirectUri           string
	Code_challenge        string
	Code_challenge_method string
	// OIDC用
	// nonce string
	// IDトークンを払い出すか否か、trueならIDトークンもfalseならOAuthでトークンだけ払い出す
	// oidc bool
}

type ClientAssertionType[T client_assertion.ClientAssertionTypeNone | client_assertion.ClientAssertionTypeClientSecretBasic | client_assertion.ClientAssertionTypeClientSecretPost | client_assertion.ClientAssertionTypeSelfSignedTlsClientAuth | client_assertion.ClientAssertionTypeClientSecretJwt | client_assertion.ClientAssertionTypePrivateKeyJwt | client_assertion.ClientAssertionTypeTlsClientAuth] interface {
	Check() bool
}

type Client struct {
	Id                  string
	Name                string
	RedirectURL         string
	Secret              string
	ClientAssertionType []ClientAssertionType[client_assertion.ClientAssertionTypeNone]
}

type User struct {
	Id          int
	Name        string
	Password    string
	Sub         string
	Name_ja     string
	Given_name  string
	Family_name string
	Locale      string
}

type AuthCode struct {
	User         string
	ClientId     string
	Scopes       string
	Redirect_uri string
	Expires_at   int64
	SessionId    string
}

type TokenCode struct {
	User       string
	ClientId   string
	Scopes     string
	Expires_at int64
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IdToken     string `json:"id_token,omitempty"`
}

type IdTokenHeader struct {
	Alg     string   `json:"alg"`                // "alg" (Algorithm) Header Parameter
	Jku     string   `json:"jku,omitempty"`      // "jku" (JWK Set URL) Header Parameter
	Jwk     string   `json:"jwk,omitempty"`      // "jwk" (JWK) Header Parameter
	Kid     string   `json:"kid,omitempty"`      // "kid" (Key ID) Header Parameter
	X5u     string   `json:"x5u,omitempty"`      // "x5u" (X.509 URL) Header Parameter
	X5c     []string `json:"x5c,omitempty"`      // "x5c" (X.509 Certificate Chain) Header Parameter
	X5t     string   `json:"x5t,omitempty"`      // "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
	X5tS256 string   `json:"x5t#S256,omitempty"` // "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter
	Typ     string   `json:"typ"`                // "typ" (Type) Header Parameter
	CTy     string   `json:"cty,omitempty"`      // "cty" (Content Type) Header Parameter
	Crit    string   `json:"crit,omitempty"`     // "crit" (Critical) Header Parameter
}
type JWT struct {
	Iss      string    `json:"iss"`           // REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case-sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	Sub      string    `json:"sub"`           // REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII [RFC20] characters in length. The sub value is a case-sensitive string.
	Aud      string    `json:"aud"`           // REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case-sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case-sensitive string.
	Exp      time.Time `json:"exp"`           // REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted by the RP when performing authentication with the OP. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a JSON [RFC8259] number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular. NOTE: The ID Token expiration time is unrelated the lifetime of the authenticated session between the RP and the OP.
	Iat      time.Time `json:"iat"`           // REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
	AuthTime time.Time `json:"auth_time"`     // Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
	Nonce    string    `json:"nonce"`         // String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case-sensitive string.
	Acr      string    `json:"acr,omitempty"` // OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. For historic reasons, the value "0" is used to indicate that there is no confidence that the same person is actually there. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value. (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered. Parties using this claim will need to agree upon the meanings of the values used, which may be context specific. The acr value is a case-sensitive string.
	Amr      string    `json:"amr,omitempty"` // OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. The amr value is an array of case-sensitive strings. Values used in the amr Claim SHOULD be from those registered in the IANA Authentication Method Reference Values registry [IANA.AMR] established by [RFC8176]; parties using this claim will need to agree upon the meanings of any unregistered values used, which may be context specific.
	Azp      string    `json:"azp,omitempty"` // OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this party. The azp value is a case-sensitive string containing a StringOrURI value. Note that in practice, the azp Claim only occurs when extensions beyond the scope of this specification are used; therefore, implementations not using such extensions are encouraged to not use azp and to ignore it when it does occur.
	// Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the access_token value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url-encode them. The at_hash value is a case-sensitive string.
	// If the ID Token is issued from the Authorization Endpoint with an access_token value, which is the case for the response_type value code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
	AtHash string `json:"at_hash,omitempty"`
	// Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the code value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is HS512, hash the code value with SHA-512, then take the left-most 256 bits and base64url-encode them. The c_hash value is a case-sensitive string.
	// If the ID Token is issued from the Authorization Endpoint with a code, which is the case for the response_type values code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
	CHash string `json:"c_hash,omitempty"`
}
