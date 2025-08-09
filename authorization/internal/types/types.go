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
	Id                  int
	AccountName         string
	Password            string
	Sub                 string
	NameJa              string
	GivenName           string
	FamilyName          string
	MiddleName          string
	Nickname            string
	PreferredUsername   string
	Profile             string
	Picture             string
	Website             string
	Gender              string
	Birthdate           time.Time
	Zoneinfo            string
	Locale              string
	StreetAddress       string
	Locality            string
	Region              string
	PostalCode          string
	Country             string
	Email               string
	EmailVerified       bool
	PhoneNumber         string
	PhoneNumberVerified bool
	UpdatedAt           int64
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
	Iss      string `json:"iss"`           // REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case-sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	Sub      string `json:"sub"`           // REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII [RFC20] characters in length. The sub value is a case-sensitive string.
	Aud      string `json:"aud"`           // REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case-sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case-sensitive string.
	Exp      int64  `json:"exp"`           // REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted by the RP when performing authentication with the OP. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a JSON [RFC8259] number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular. NOTE: The ID Token expiration time is unrelated the lifetime of the authenticated session between the RP and the OP.
	Iat      int64  `json:"iat"`           // REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
	AuthTime int64  `json:"auth_time"`     // Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
	Nonce    string `json:"nonce"`         // String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case-sensitive string.
	Acr      string `json:"acr,omitempty"` // OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. For historic reasons, the value "0" is used to indicate that there is no confidence that the same person is actually there. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value. (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered. Parties using this claim will need to agree upon the meanings of the values used, which may be context specific. The acr value is a case-sensitive string.
	Amr      string `json:"amr,omitempty"` // OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. The amr value is an array of case-sensitive strings. Values used in the amr Claim SHOULD be from those registered in the IANA Authentication Method Reference Values registry [IANA.AMR] established by [RFC8176]; parties using this claim will need to agree upon the meanings of any unregistered values used, which may be context specific.
	Azp      string `json:"azp,omitempty"` // OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this party. The azp value is a case-sensitive string containing a StringOrURI value. Note that in practice, the azp Claim only occurs when extensions beyond the scope of this specification are used; therefore, implementations not using such extensions are encouraged to not use azp and to ignore it when it does occur.
	// Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the access_token value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the access_token value with SHA-256, then take the left-most 128 bits and base64url-encode them. The at_hash value is a case-sensitive string.
	// If the ID Token is issued from the Authorization Endpoint with an access_token value, which is the case for the response_type value code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
	AtHash string `json:"at_hash,omitempty"`
	// Code hash value. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the code value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is HS512, hash the code value with SHA-512, then take the left-most 256 bits and base64url-encode them. The c_hash value is a case-sensitive string.
	// If the ID Token is issued from the Authorization Endpoint with a code, which is the case for the response_type values code id_token and code id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
	CHash string `json:"c_hash,omitempty"`
}

type UserInfoStandardClaimsProfile struct {
	Name              string `json:"name,omitempty"`               // End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
	GivenName         string `json:"given_name,omitempty"`         // Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
	FamilyName        string `json:"family_name,omitempty"`        // Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
	MiddleName        string `json:"middle_name,omitempty"`        // Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
	Nickname          string `json:"nickname,omitempty"`           // Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
	PreferredUsername string `json:"preferred_username,omitempty"` // Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
	Profile           string `json:"profile,omitempty"`            // URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
	Picture           string `json:"picture,omitempty"`            // URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
	Website           string `json:"website,omitempty"`            // URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
	Gender            string `json:"gender,omitempty"`             // End-User's gender. Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
	Birthdate         string `json:"birthdate,omitempty"`          // End-User's birthday, represented as an ISO 8601-1 [ISO8601‑1] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related function, providing just year can result in varying month and day, so the implementers need to take this factor into account to correctly process the dates.
	Zoneinfo          string `json:"zoneinfo,omitempty"`           // String from IANA Time Zone Database [IANA.time‑zones] representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
	Locale            string `json:"locale,omitempty"`             // End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639 Alpha-2 [ISO639] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
	UpdatedAt         int64  `json:"updated_at,omitempty"`         // Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
}
type UserInfoStandardClaimsAddress struct {
	Formatted     string `json:"formatted,omitempty"`      // Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	StreetAddress string `json:"street_address,omitempty"` // Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
	Locality      string `json:"locality,omitempty"`       // City or locality component.
	Region        string `json:"region,omitempty"`         // State, province, prefecture, or region component.
	PostalCode    string `json:"postal_code,omitempty"`    // Zip code or postal code component.
	Country       string `json:"country,omitempty"`        // Country name component.
}
type UserInfoStandardClaimsEmail struct {
	Email         string `json:"email,omitempty"`          // End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
	EmailVerified bool   `json:"email_verified,omitempty"` // True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context specific, and dependent upon the trust framework or contractual agreements within which the parties are operating.
}
type UserInfoStandardClaimsPhone struct {
	PhoneNumber         string `json:"phone_number,omitempty"`          // End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"` // True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed. The means by which a phone number is verified is context specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
}
type UserInfoStandardClaims struct {
	Sub string `json:"sub,omitempty"` // Subject - Identifier for the End-User at the Issuer.
	UserInfoStandardClaimsProfile
	UserInfoStandardClaimsEmail
	UserInfoStandardClaimsPhone
	Address *UserInfoStandardClaimsAddress `json:"address,omitempty"` // object	End-User's preferred postal address. The value of the address member is a JSON [RFC8259] structure containing some or all of the members defined in Section 5.1.1.
}
type UserInfo struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	UserInfoStandardClaims
}
