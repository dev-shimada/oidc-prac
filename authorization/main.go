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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dev-shimada/oidc-prac/authorization/internal/jwt"
	"github.com/dev-shimada/oidc-prac/authorization/internal/types"
	"github.com/google/uuid"
	"golang.org/x/exp/slices"
)

func issuerBaseURL() string {
	if v := os.Getenv("ISSUER_BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:49151"
}

const (
	AUTH_CODE_DURATION    = 300
	ACCESS_TOKEN_DURATION = 3600
)

var clients = map[string]types.Client{
	"1234": { // Client ID
		Name:                "test",
		RedirectURL:         "http://localhost:49150/callback",
		ClientAssertionType: []types.ClientAssertionType[types.ClientAssertionTypeNone]{types.ClientAssertionTypeClientSecretBasic{Secret: "secret"}},
	},
}

func corsMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello, World!"))
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
		Handler: corsMiddleware(mux),
	}

	slog.Info("Server is running at :49151 Press CTRL-C to exit.")
	go func() { _ = srv.ListenAndServe() }()

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
		CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	}{
		Issuer:                            issuerBaseURL(),
		AuthorizationEndpoint:             issuerBaseURL() + "/auth",
		TokenEndpoint:                     issuerBaseURL() + "/token",
		UserinfoEndpoint:                  issuerBaseURL() + "/userinfo",
		JwksUri:                           issuerBaseURL() + "/certs",
		ScopesSupported:                   []string{"openid", "profile", "email", "address", "phone"},
		ResponseTypesSupported:            []string{"code", "code id_token"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IdTokenSigningAlgValuesSupported:  []string{"HS256", "RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "none"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
	}
	res, err := json.Marshal(config)
	if err != nil {
		slog.Error(fmt.Sprintf("json marshal err: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	_, err = w.Write(res)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to write response: %v", err))
		http.Error(w, "Failed to write response: "+err.Error(), http.StatusInternalServerError)
		return
	}
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
			_, _ = w.Write(fmt.Appendf(nil, "invalid_request. %s is missing", v))
			return
		}
	}
	// client id の一致確認
	if _, ok := clients[query.Get("client_id")]; !ok {
		slog.Error(fmt.Sprintf("client_id %s is not found", query.Get("client_id")))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid_request. client_id is not found.\n"))
		return
	}

	// レスポンスタイプの検証（認可コードフローとハイブリッドフロー）
	responseType := query.Get("response_type")
	if responseType != "code" && responseType != "code id_token" {
		slog.Error(fmt.Sprintf("unsupported response_type: %s", responseType))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("unsupported_response_type"))
		return
	}

	// PKCE パラメータの検証
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	// code_challenge が提供されている場合は code_challenge_method も必須
	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain" // デフォルトは plain
		}
		// サポートされているメソッドかチェック
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			slog.Error(fmt.Sprintf("unsupported code_challenge_method: %s", codeChallengeMethod))
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("unsupported_code_challenge_method"))
			return
		}
	}
	sessionId := uuid.New().String()
	// セッションを保存しておく
	session := types.Session{
		Client:                query.Get("client_id"),
		State:                 query.Get("state"),
		Nonce:                 query.Get("nonce"),
		Scopes:                query.Get("scope"),
		RedirectUri:           query.Get("redirect_uri"),
		Code_challenge:        codeChallenge,
		Code_challenge_method: codeChallengeMethod,
		ResponseType:          responseType,
	}
	sessionList[sessionId] = session

	// CookieにセッションIDをセット
	cookie := &http.Cookie{
		Name:     "session",
		Path:     "/",
		Value:    sessionId,
		HttpOnly: true,
		// Secure:   req.TLS != nil,
		Secure:   false,
		Expires:  time.Now().Add(5 * time.Minute),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// 既存のセッションがあり、認証済みの場合は認可画面を表示
	if session.AuthenticatedUser != "" {
		// 認可画面を表示
		showConsentPage(w, session)
		return
	}

	// 未認証の場合はログイン画面を表示
	var templates = make(map[string]*template.Template)
	var err error
	if templates["login"], err = template.ParseFiles("login.html"); err != nil {
		slog.Error(fmt.Sprintf("Failed to parse login template: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	if err := templates["login"].Execute(w, struct {
		ClientId string
		Scope    string
	}{
		ClientId: session.Client,
		Scope:    session.Scopes,
	}); err != nil {
		slog.Error(fmt.Sprintf("Failed to execute login template: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	slog.Info("return login page...")
}

func showConsentPage(w http.ResponseWriter, session types.Session) {
	var templates = make(map[string]*template.Template)
	var err error
	if templates["consent"], err = template.ParseFiles("consent.html"); err != nil {
		slog.Error(fmt.Sprintf("Failed to parse consent template: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}

	// スコープの説明を生成
	type ScopeInfo struct {
		Name        string
		Description string
	}

	scopeDescriptions := map[string]string{
		"openid":  "あなたの基本的な識別情報（ID）にアクセスします",
		"profile": "あなたの名前、プロフィール画像などの基本プロフィール情報にアクセスします",
		"email":   "あなたのメールアドレスにアクセスします",
		"phone":   "あなたの電話番号にアクセスします",
		"address": "あなたの住所情報にアクセスします",
	}

	var scopes []ScopeInfo
	if session.Scopes != "" {
		for _, scope := range strings.Split(session.Scopes, " ") {
			if desc, ok := scopeDescriptions[scope]; ok {
				scopes = append(scopes, ScopeInfo{
					Name:        scope,
					Description: desc,
				})
			} else {
				scopes = append(scopes, ScopeInfo{
					Name:        scope,
					Description: "カスタムスコープ",
				})
			}
		}
	}

	if err := templates["consent"].Execute(w, struct {
		ClientId string
		Scope    string
		Scopes   []ScopeInfo
	}{
		ClientId: session.Client,
		Scope:    session.Scopes,
		Scopes:   scopes,
	}); err != nil {
		slog.Error(fmt.Sprintf("Failed to execute consent template: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	slog.Info("return consent page...")
}

var user = types.User{
	Id:          1,
	AccountName: "name",
	Password:    "pw",
	Sub:         "11111111",
	NameJa:      "徳川慶喜",
	GivenName:   "慶喜",
	FamilyName:  "徳川",
	Locale:      "JP",
}

var AuthCodeList = make(map[string]types.AuthCode)

func authCheck(w http.ResponseWriter, req *http.Request) {
	// セッションクッキーを取得
	cookie, err := req.Cookie("session")
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to get session cookie: %v", err))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("session cookie is not found"))
		return
	}

	session, ok := sessionList[cookie.Value]
	if !ok {
		slog.Error("session not found")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid session"))
		return
	}

	// ユーザーのアクション確認
	action := req.FormValue("action")

	// 未認証の場合：認証処理
	if session.AuthenticatedUser == "" {
		loginUser := req.FormValue("username")
		password := req.FormValue("password")

		if loginUser != user.AccountName || password != user.Password {
			slog.Error(fmt.Sprintf("login failed: %s, %s", loginUser, password))
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("login failed"))
			return
		}

		// 認証成功：セッションにユーザー情報を保存
		session.AuthenticatedUser = loginUser
		session.AuthTime = time.Now().Unix()
		sessionList[cookie.Value] = session

		slog.Info("authentication successful", "user", loginUser)

		// 認可画面を表示
		showConsentPage(w, session)
		return
	}

	// 認証済みの場合：認可処理
	if action == "deny" {
		// ユーザーが拒否した場合
		slog.Info("user denied authorization")
		location := fmt.Sprintf("%s?error=access_denied&error_description=The+resource+owner+denied+the+request&state=%s", session.RedirectUri, session.State)
		http.Redirect(w, req, location, http.StatusFound)
		return
	}

	// 認可コードを生成
	authCodeString := uuid.New().String()
	authData := types.AuthCode{
		User:         session.AuthenticatedUser,
		ClientId:     session.Client,
		Scopes:       session.Scopes,
		Redirect_uri: session.RedirectUri,
		Expires_at:   time.Now().Add(AUTH_CODE_DURATION * time.Second).Unix(),
		SessionId:    cookie.Value,
		Nonce:        session.Nonce,
		AuthTime:     session.AuthTime,
	}
	// 認可コードを保存
	AuthCodeList[authCodeString] = authData

	slog.Info("auth code accepted", "authCode", authCodeString)

	switch session.ResponseType {
	// ハイブリッドフロー
	case "code id_token":
		d := sha256.Sum256([]byte(authCodeString))
		digest := d[:]
		leftHalf := digest[:len(digest)/2]
		hashClaim := base64.RawURLEncoding.EncodeToString(leftHalf)

		jws := &jwt.JWS{
			Header: jwt.IdTokenHeader{
				Alg: "RS256",
				Typ: "JWT",
			},
			Payload: jwt.JWT{
				Iss:      issuerBaseURL(),
				Sub:      user.Sub,
				Aud:      "1234",
				Exp:      time.Now().Add(ACCESS_TOKEN_DURATION * time.Second).Unix(),
				Iat:      time.Now().Unix(),
				AuthTime: authData.AuthTime,
				Nonce:    session.Nonce,
				CHash:    hashClaim,
			},
		}
		idToken, _ := jws.Make()

		location := fmt.Sprintf("%s?code=%s&id_token=%s&state=%s", session.RedirectUri, authCodeString, idToken, session.State)
		slog.Info("redirect to client (hybrid flow)", "location", location)
		http.Redirect(w, req, location, http.StatusFound)
	// 認可コードフロー
	case "code":
		location := fmt.Sprintf("%s?code=%s&state=%s", session.RedirectUri, authCodeString, session.State)
		slog.Info("redirect to client (authorization code flow)", "location", location)
		http.Redirect(w, req, location, http.StatusFound)
	default:
		slog.Error(fmt.Sprintf("unsupported response_type during redirect: %s", session.ResponseType))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("unsupported_response_type"))
		return
	}
}

type CodeChallengeMethod string

const (
	CodeChallengePlain CodeChallengeMethod = "plain"
	CodeChallengeS256  CodeChallengeMethod = "S256"
)

func validateCodeChallenge(verifier, challenge string, method CodeChallengeMethod) bool {
	if challenge == "" {
		return false
	}

	switch method {
	case CodeChallengePlain:
		return verifier == challenge
	case CodeChallengeS256:
		h := sha256.New()
		h.Write([]byte(verifier))
		hashed := h.Sum(nil)
		expected := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)
		return expected == challenge
	default:
		return false
	}
}

func base64URLEncode(verifier string, ccm CodeChallengeMethod) string {
	if ccm == CodeChallengePlain {
		return verifier
	}

	h := sha256.New()
	h.Write([]byte(verifier))
	hashed := h.Sum(nil)

	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)

	return codeChallenge
}

var TokenCodeList = make(map[string]types.TokenCode)

// トークンを発行するエンドポイント
func token(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to parse form: %v", err))
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	query := req.Form

	var (
		requiredParameter []string = []string{"grant_type", "code", "client_id", "redirect_uri"}
		client            types.Client
		clientId          string
		code              string
	)
	switch {
	case req.Header.Get("Authorization") != "":
		requiredParameter = []string{"grant_type"}
		encoded := strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			clientId = strings.SplitN(string(decoded), ":", 2)[0]
			client = clients[clientId]
		} else {
			slog.Error(fmt.Sprintf("Failed to decode Authorization header: %v", err))
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid_request. Authorization header is not valid.\n"))
			return
		}
		code = req.FormValue("code")
	case query.Get("client_id") != "":
		clientId = query.Get("client_id")
		client = clients[query.Get(clientId)]
		code = query.Get("code")
	}
	slog.Info(fmt.Sprintf("clientId: %s, code: %s", clientId, code))
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			slog.Error(fmt.Sprintf("%s is missing", v))
			w.WriteHeader(http.StatusBadRequest)
			b := make([]byte, 0)
			_, _ = w.Write(fmt.Appendf(b, "invalid_request. %s is missing\n", v))
			return
		}
	}

	// クライアント認証
	for _, v := range client.ClientAssertionType {
		if !v.Check(*req) {
			slog.Error("client assertion type is not match")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid_request. client assertion type is not match.\n"))
			return
		}
	}

	// 認可コードフローだけサポート
	if query.Get("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid_request. not support type.\n"))
	}

	// 保存していた認可コードのデータを取得。なければエラーを返す
	slog.Info(fmt.Sprintf("auth code is %s", code))
	v, ok := AuthCodeList[code]
	if !ok {
		slog.Error("auth code isn't exist")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("no authrization code"))
	}

	// 認可リクエスト時のクライアントIDと比較
	if v.ClientId != clientId {
		slog.Error("client_id not match")
		w.WriteHeader(http.StatusBadRequest)
		// w.Write([]byte("invalid_request. client_id not match.\n"))
		_, _ = w.Write([]byte("client_id is not match"))
	}

	// 認可リクエスト時のリダイレクトURIと比較
	if v.Redirect_uri != query.Get("redirect_uri") {
		slog.Error("redirect_uri not match")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid_request. redirect_uri not match.\n"))
	}

	// 認可コードの有効期限を確認
	if v.Expires_at < time.Now().Unix() {
		slog.Error("authcode expire")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid_request. auth code time limit is expire.\n"))
	}

	// PKCEのチェック
	session := sessionList[AuthCodeList[query.Get("code")].SessionId]
	if session.Code_challenge != "" {
		codeVerifier := query.Get("code_verifier")
		if codeVerifier == "" {
			slog.Error("code_verifier is missing for PKCE flow")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid_request. code_verifier is missing"))
			return
		}

		method := CodeChallengeMethod(session.Code_challenge_method)
		if method == "" {
			method = CodeChallengePlain // デフォルト
		}

		if !validateCodeChallenge(codeVerifier, session.Code_challenge, method) {
			slog.Error(fmt.Sprintf("PKCE verification failed: verifier=%s, challenge=%s, method=%s",
				codeVerifier, session.Code_challenge, method))
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid_grant. PKCE verification failed"))
			return
		}
		slog.Info("PKCE verification successful")
	}

	tokenString := uuid.New().String()
	expireTime := time.Now().Add(ACCESS_TOKEN_DURATION * time.Second).Unix()

	tokenInfo := types.TokenCode{
		User:       v.User,
		ClientId:   v.ClientId,
		Scopes:     v.Scopes,
		Expires_at: expireTime,
	}
	TokenCodeList[tokenString] = tokenInfo
	// 認可コードを削除
	delete(AuthCodeList, query.Get("code"))

	d := sha256.Sum256([]byte(tokenString))
	digest := d[:]
	leftHalf := digest[:len(digest)/2]
	hashClaim := base64.RawURLEncoding.EncodeToString(leftHalf)

	jws := &jwt.JWS{
		Header: jwt.IdTokenHeader{
			Alg: "RS256",
			Typ: "JWT",
		},
		Payload: jwt.JWT{
			Iss:      issuerBaseURL(),
			Sub:      user.Sub,
			Aud:      "1234",
			Exp:      time.Now().Add(ACCESS_TOKEN_DURATION * time.Second).Unix(),
			Iat:      time.Now().Unix(),
			AuthTime: v.AuthTime,
			Nonce:    v.Nonce,
			AtHash:   hashClaim,
		},
	}
	idToken, _ := jws.Make()

	tokenResp := types.TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expireTime,
		IdToken:     idToken,
	}
	resp, err := json.Marshal(tokenResp)
	if err != nil {
		slog.Error(fmt.Sprintf("json marshal err: %v", err))
	}

	slog.Info("token ok to client", "clientId", v.ClientId, "token", string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(resp)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to write token response: %v", err))
		http.Error(w, "Failed to write token response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func certs(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(jwt.MakeJWK())
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to write JWK response: %v", err))
		http.Error(w, "Failed to write JWK response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func userinfo(w http.ResponseWriter, req *http.Request) {
	var accessToken string

	h := req.Header.Get("Authorization")
	if h != "" {
		// Authorization ヘッダーから Bearer トークンを取得
		tmp := strings.Split(h, " ")
		if len(tmp) == 2 {
			accessToken = tmp[1]
		}
	} else {
		// リクエストボディから access_token を取得
		if err := req.ParseForm(); err == nil {
			accessToken = req.FormValue("access_token")
		}
	}

	// トークンがあるか確認
	v, ok := TokenCodeList[accessToken]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("token is wrong.\n"))
		return
	}

	// トークンの有効期限が切れてないか
	if v.Expires_at < time.Now().Unix() {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("token is expire.\n"))
		return
	}

	scopes := strings.Split(v.Scopes, " ")
	// スコープが正しいか
	if !slices.Contains(scopes, "openid") {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("openid scope is required.\n"))
		return
	}

	// ユーザ情報を返す
	var m = types.UserInfo{
		UserInfoStandardClaims: types.UserInfoStandardClaims{
			Sub: user.Sub,
		},
		Iss: issuerBaseURL(),
		Aud: "1234",
	}
	if slices.Contains(scopes, "profile") {
		m.UserInfoStandardClaimsProfile = types.UserInfoStandardClaimsProfile{
			Name:              user.NameJa,
			GivenName:         user.GivenName,
			FamilyName:        user.FamilyName,
			MiddleName:        user.MiddleName,
			Nickname:          user.Nickname,
			PreferredUsername: user.PreferredUsername,
			Profile:           user.Profile,
			Picture:           user.Picture,
			Website:           user.Website,
			Gender:            user.Gender,
			Zoneinfo:          user.Zoneinfo,
			Locale:            user.Locale,
			UpdatedAt:         user.UpdatedAt,
		}
		if !user.Birthdate.IsZero() {
			m.Birthdate = user.Birthdate.Format("2006-01-02")
		}
	}
	if slices.Contains(scopes, "email") {
		m.UserInfoStandardClaimsEmail = types.UserInfoStandardClaimsEmail{
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
		}
	}
	if slices.Contains(scopes, "phone") {
		m.UserInfoStandardClaimsPhone = types.UserInfoStandardClaimsPhone{
			PhoneNumber:         user.PhoneNumber,
			PhoneNumberVerified: user.PhoneNumberVerified,
		}
	}
	if slices.Contains(scopes, "address") {
		m.Address = &types.UserInfoStandardClaimsAddress{
			Formatted:     fmt.Sprintf("%s\n%s, %s %s\n%s", user.StreetAddress, user.Locality, user.Region, user.PostalCode, user.Country),
			StreetAddress: user.StreetAddress,
			Locality:      user.Locality,
			Region:        user.Region,
			PostalCode:    user.PostalCode,
			Country:       user.Country,
		}
	}

	buf, _ := json.MarshalIndent(m, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(buf)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to write user info response: %v", err))
		http.Error(w, "Failed to write user info response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
