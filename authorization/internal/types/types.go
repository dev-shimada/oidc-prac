package types

import "github.com/dev-shimada/oidc-prac/authorization/internal/client_assertion"

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
