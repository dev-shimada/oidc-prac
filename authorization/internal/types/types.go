package types

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

type ClientAssertionTypeNone struct{}
type ClientAssertionTypeClientSecretBasic struct{}
type ClientAssertionTypeClientSecretPost struct{}
type ClientAssertionTypeClientSecretJwt struct{}
type ClientAssertionTypePrivateKeyJwt struct{}
type ClientAssertionTypeTlsClientAuth struct{}
type ClientAssertionTypeSelfSignedTlsClientAuth struct{}

func (c ClientAssertionTypeNone) Check() bool {
	return true
}
func (c ClientAssertionTypeClientSecretBasic) Check() bool {
	// TODO: Implement check logic for ClientSecretBasic
	return false
}
func (c ClientAssertionTypeClientSecretPost) Check() bool {
	// TODO: Implement check logic for ClientSecretPost
	return false
}
func (c ClientAssertionTypeClientSecretJwt) Check() bool {
	// TODO: Implement check logic for ClientSecretJwt
	return false
}
func (c ClientAssertionTypePrivateKeyJwt) Check() bool {
	// TODO: Implement check logic for PrivateKeyJwt
	return false
}
func (c ClientAssertionTypeSelfSignedTlsClientAuth) Check() bool {
	// TODO: Implement check logic for SelfSignedTlsClientAuth
	return false
}
func (c ClientAssertionTypeTlsClientAuth) Check() bool {
	// TODO: Implement check logic for TlsClientAuth
	return false
}

type ClientAssertionType[T ClientAssertionTypeNone | ClientAssertionTypeClientSecretBasic | ClientAssertionTypeClientSecretPost | ClientAssertionTypeSelfSignedTlsClientAuth | ClientAssertionTypeClientSecretJwt | ClientAssertionTypePrivateKeyJwt | ClientAssertionTypeTlsClientAuth] interface {
	Check() bool
}

type Client struct {
	Id                  string
	Name                string
	RedirectURL         string
	Secret              string
	ClientAssertionType []ClientAssertionType[ClientAssertionTypeNone]
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
