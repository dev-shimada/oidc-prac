package client_assertion

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
