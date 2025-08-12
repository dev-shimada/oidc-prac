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
