package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dev-shimada/oidc-prac/authorization/internal/client_assertion"
	"github.com/dev-shimada/oidc-prac/authorization/internal/jwt"
	"github.com/dev-shimada/oidc-prac/authorization/internal/types"
	"github.com/google/uuid"
)

const (
	//SCOPE                 = "readonly"
	SCOPE                 = "https://www.googleapis.com/auth/photoslibrary.readonly"
	AUTH_CODE_DURATION    = 300
	ACCESS_TOKEN_DURATION = 3600
)

var clientInfo = types.Client{
	Id:                  "1234",
	Name:                "test",
	RedirectURL:         "http://localhost:49150/callback",
	Secret:              "secret",
	ClientAssertionType: []types.ClientAssertionType[client_assertion.ClientAssertionTypeNone]{client_assertion.ClientAssertionTypeNone{}},
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("/.well-known/openid-configuration", wellKnownOpenIdConfiguration)
	mux.HandleFunc("/auth", auth)
	mux.HandleFunc("/authcheck", authCheck)
	mux.HandleFunc("/token", token)
	mux.HandleFunc("/certs", certs)
	mux.HandleFunc("/userinfo", userinfo)

	// Wait here until CTRL+C or other term signal is received
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	// defer stop()

	srv := &http.Server{
		Addr:    ":49151",
		Handler: mux,
	}

	slog.Info("Server is running at :49151 Press CTRL-C to exit.")
	go srv.ListenAndServe()

	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Info(fmt.Sprintf("HTTP server Shutdown: %v", err))
	}

}

func wellKnownOpenIdConfiguration(w http.ResponseWriter, req *http.Request) {
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	config := struct {
		Issuer                                     string   `json:"issuer"`
		AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
		TokenEndpoint                              string   `json:"token_endpoint"`
		UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
		JwksUri                                    string   `json:"jwks_uri"`
		RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
		ScopesSupported                            []string `json:"scopes_supported,omitempty"`
		ResponseTypesSupported                     []string `json:"response_types_supported"`
		ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
		GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
		AcrValuesSupported                         []string `json:"acr_values_supported,omitempty"`
		SubjectTypesSupported                      []string `json:"subject_types_supported"`
		IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
		IdTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
		IdTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
		UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
		UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
		UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
		RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
		RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
		RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`
		TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
		TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
		DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`
		ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
		ClaimsSupported                            []string `json:"claims_supported,omitempty"`
		ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
		ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`
		UiLocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
		ClaimsParameterSupported                   bool     `json:"claims_parameter_supported,omitempty"`
		RequestParameterSupported                  bool     `json:"request_parameter_supported,omitempty"`
		RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported,omitempty"`
		RequireRequestUriRegistration              bool     `json:"require_request_uri_registration,omitempty"`
		OpPolicyUri                                string   `json:"op_policy_uri,omitempty"`
		OpTosUri                                   string   `json:"op_tos_uri,omitempty"`
	}{
		Issuer:                           "http://localhost:49151",
		AuthorizationEndpoint:            "http://localhost:49151/auth",
		TokenEndpoint:                    "http://localhost:49151/token",
		UserinfoEndpoint:                 "http://localhost:49151/userinfo",
		JwksUri:                          "http://localhost:49151/certs",
		ResponseTypesSupported:           []string{"code id_token"},
		ScopesSupported:                  []string{"openid", "profile", "email", "address", "phone"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}
	res, err := json.Marshal(config)
	if err != nil {
		slog.Error(fmt.Sprintf("json marshal err: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}
	w.Write(res)
}

var sessionList = make(map[string]types.Session)

func auth(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	requiredParameter := []string{"response_type", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			slog.Error(fmt.Sprintf("%s is missing", v))
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. %s is missing", v)))
			return
		}
	}
	// client id の一致確認
	if clientInfo.Id != query.Get("client_id") {
		slog.Error(fmt.Sprintf("want: %s, got: %s", clientInfo.Id, query.Get("client_id")))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client_id is not match"))
		return
	}
	// レスポンスタイプはハイブリッドフローだけをサポート
	if query.Get("response_type") != "code id_token" {
		slog.Error(fmt.Sprintf("want: code id_token, got: %s", query.Get("response_type")))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("only support code id_token"))
		return
	}
	sessionId := uuid.New().String()
	// セッションを保存しておく
	session := types.Session{
		Client:                query.Get("client_id"),
		State:                 query.Get("state"),
		Scopes:                query.Get("scope"),
		RedirectUri:           query.Get("redirect_uri"),
		Code_challenge:        query.Get("code_challenge"),
		Code_challenge_method: query.Get("code_challenge_method"),
	}
	sessionList[sessionId] = session

	// CookieにセッションIDをセット
	cookie := &http.Cookie{
		Name:     "session",
		Path:     "/",
		Value:    sessionId,
		HttpOnly: true,
		// Secure:   req.TLS != nil,
		Expires:  time.Now().Add(5 * time.Minute),
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// ログイン&権限認可の画面を戻す
	var templates = make(map[string]*template.Template)
	var err error
	if templates["login"], err = template.ParseFiles("login.html"); err != nil {
		slog.Error(fmt.Sprintf("Failed to parse login template: %v", err))
	}
	if err := templates["login"].Execute(w, struct {
		ClientId string
		Scope    string
	}{
		ClientId: session.Client,
		Scope:    session.Scopes,
	}); err != nil {
		slog.Error(fmt.Sprintf("Failed to execute login template: %v", err))
	}
	slog.Info("return login page...")
}

var user = types.User{
	Id:          1,
	Name:        "name",
	Password:    "pw",
	Sub:         "11111111",
	Name_ja:     "徳川慶喜",
	Given_name:  "慶喜",
	Family_name: "徳川",
	Locale:      "ja",
}

var AuthCodeList = make(map[string]types.AuthCode)

func authCheck(w http.ResponseWriter, req *http.Request) {

	loginUser := req.FormValue("username")
	password := req.FormValue("password")

	if loginUser != user.Name || password != user.Password {
		slog.Error(fmt.Sprintf("login failed: %s, %s", loginUser, password))
		w.Write([]byte("login failed"))
	} else {
		cookie, err := req.Cookie("session")
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to get session cookie: %v", err))
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("session cookie is not found"))
			return
		}

		v := sessionList[cookie.Value]

		authCodeString := uuid.New().String()
		authData := types.AuthCode{
			User:         loginUser,
			ClientId:     v.Client,
			Scopes:       v.Scopes,
			Redirect_uri: v.RedirectUri,
			Expires_at:   time.Now().Unix() + 300,
			SessionId:    cookie.Value,
		}
		// 認可コードを保存
		AuthCodeList[authCodeString] = authData

		slog.Info("auth code accepted", "authCode", authCodeString)

		location := fmt.Sprintf("%s?code=%s&state=%s", v.RedirectUri, authCodeString, v.State)
		http.Redirect(w, req, location, http.StatusFound)
	}
}

type CodeChallengeMethod string

const (
	CodeChallengePlain CodeChallengeMethod = "plain"
	CodeChallengeS256  CodeChallengeMethod = "S256"
)

// https://auth0.com/docs/authorization/flows/call-your-api-using-the-authorization-code-flow-with-pkce#javascript-sample
func base64URLEncode(verifier string, ccm CodeChallengeMethod) string {
	// hash := sha256.Sum256([]byte(verifier))
	// return base64.RawURLEncoding.EncodeToString(hash[:])
	// If the code challenge method is "plain", the code challenge is the same as the code verifier
	if ccm == CodeChallengePlain {
		return verifier
	}

	// Hash the code verifier using SHA-256
	h := sha256.New()
	h.Write([]byte(verifier))
	hashed := h.Sum(nil)

	// Base64-url-encode the hash and remove any padding
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)

	return codeChallenge
}

var TokenCodeList = make(map[string]types.TokenCode)

// トークンを発行するエンドポイント
func token(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	query := req.Form

	requiredParameter := []string{"grant_type", "code", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			slog.Error(fmt.Sprintf("%s is missing", v))
			w.WriteHeader(http.StatusBadRequest)
			b := make([]byte, 0)
			w.Write(fmt.Appendf(b, "invalid_request. %s is missing\n", v))
			return
		}
	}

	// 認可コードフローだけサポート
	if query.Get("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. not support type.\n"))
	}

	// 保存していた認可コードのデータを取得。なければエラーを返す
	slog.Info(fmt.Sprintf("auth code is %s", query.Get("code")))
	v, ok := AuthCodeList[query.Get("code")]
	if !ok {
		slog.Error("auth code isn't exist")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("no authrization code"))
	}

	// 認可リクエスト時のクライアントIDと比較
	if v.ClientId != query.Get("client_id") {
		slog.Error("client_id not match")
		w.WriteHeader(http.StatusBadRequest)
		// w.Write([]byte("invalid_request. client_id not match.\n"))
		w.Write([]byte("client_id is not match"))
	}

	// 認可リクエスト時のリダイレクトURIと比較
	if v.Redirect_uri != query.Get("redirect_uri") {
		slog.Error("redirect_uri not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. redirect_uri not match.\n"))
	}

	// 認可コードの有効期限を確認
	if v.Expires_at < time.Now().Unix() {
		slog.Error("authcode expire")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request. auth code time limit is expire.\n"))
	}

	for _, v := range clientInfo.ClientAssertionType {
		if !v.Check() {
			// クライアント認証のチェック
			slog.Error("client assertion type is not match")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid_request. client assertion type is not match.\n"))
			return
		}
	}

	// // clientシークレットの確認
	// if clientInfo.Secret != query.Get("client_secret") {
	// 	slog.Error("client_secret is not match.")
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	w.Write([]byte("invalid_request. client_secret is not match.\n"))
	// }

	// PKCEのチェック
	// clientから送られてきたverifyをsh256で計算&base64urlエンコードしてから
	// 認可リクエスト時に送られてきてセッションに保存しておいたchallengeと一致するか確認
	session := sessionList[AuthCodeList[query.Get("code")].SessionId]
	if session.Code_challenge != base64URLEncode(query.Get("code_verifier"), CodeChallengeS256) {
		slog.Error(fmt.Sprintf("PKCE verification failed: %s, %s", session.Code_challenge, base64URLEncode(query.Get("code_verifier"), CodeChallengeS256)))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("PKCE check is err..."))
	}

	tokenString := uuid.New().String()
	expireTime := time.Now().Unix() + ACCESS_TOKEN_DURATION

	tokenInfo := types.TokenCode{
		User:       v.User,
		ClientId:   v.ClientId,
		Scopes:     v.Scopes,
		Expires_at: expireTime,
	}
	TokenCodeList[tokenString] = tokenInfo
	// 認可コードを削除
	delete(AuthCodeList, query.Get("code"))

	tokenResp := types.TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expireTime,
	}
	resp, err := json.Marshal(tokenResp)
	if err != nil {
		slog.Error(fmt.Sprintf("json marshal err: %v", err))
	}

	slog.Info("token ok to client", "clientId", v.ClientId, "token", string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func certs(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(jwt.MakeJWK())
}

func userinfo(w http.ResponseWriter, req *http.Request) {
	h := req.Header.Get("Authorization")
	tmp := strings.Split(h, " ")

	// トークンがあるか確認
	v, ok := TokenCodeList[tmp[1]]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("token is wrong.\n"))
		return
	}

	// トークンの有効期限が切れてないか
	if v.Expires_at < time.Now().Unix() {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("token is expire.\n"))
		return
	}

	// スコープが正しいか、openid profileで固定
	if v.Scopes != "openid profile" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("scope is not permit.\n"))
		return
	}

	// ユーザ情報を返す
	var m = map[string]interface{}{
		"sub":         user.Sub,
		"name":        user.Name_ja,
		"given_name":  user.Given_name,
		"family_name": user.Family_name,
		"locale":      user.Locale,
	}
	buf, _ := json.MarshalIndent(m, "", "  ")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
}
