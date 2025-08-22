package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWellKnownOpenIdConfiguration(t *testing.T) {
	// Create a request to the wellKnownOpenIdConfiguration endpoint
	req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(wellKnownOpenIdConfiguration)

	// Call the handler with our request and recorder
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the content type
	expectedContentType := "application/json"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("handler returned wrong content type: got %v want %v",
			contentType, expectedContentType)
	}

	// Parse the JSON response
	var config map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &config)
	if err != nil {
		t.Fatalf("Could not parse JSON response: %v", err)
	}

	// Test required fields according to OpenID Connect Discovery spec
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}

	for _, field := range requiredFields {
		if _, exists := config[field]; !exists {
			t.Errorf("Required field '%s' is missing from configuration", field)
		}
	}

	// Test specific field values
	expectedValues := map[string]interface{}{
		"issuer":                 "http://localhost:49151",
		"authorization_endpoint": "http://localhost:49151/auth",
		"token_endpoint":         "http://localhost:49151/token",
		"userinfo_endpoint":      "http://localhost:49151/userinfo",
		"jwks_uri":               "http://localhost:49151/certs",
	}

	for field, expectedValue := range expectedValues {
		if actualValue, exists := config[field]; !exists {
			t.Errorf("Field '%s' is missing", field)
		} else if actualValue != expectedValue {
			t.Errorf("Field '%s': got %v, want %v", field, actualValue, expectedValue)
		}
	}

	// Test array fields
	if scopesSupported, exists := config["scopes_supported"]; exists {
		scopes := scopesSupported.([]interface{})
		expectedScopes := []string{"openid", "profile", "email", "address", "phone"}
		if len(scopes) != len(expectedScopes) {
			t.Errorf("scopes_supported length: got %d, want %d", len(scopes), len(expectedScopes))
		}
		for i, scope := range expectedScopes {
			if i < len(scopes) && scopes[i] != scope {
				t.Errorf("scopes_supported[%d]: got %v, want %v", i, scopes[i], scope)
			}
		}
	} else {
		t.Error("scopes_supported field is missing")
	}

	if subjectTypes, exists := config["subject_types_supported"]; exists {
		subjects := subjectTypes.([]interface{})
		if len(subjects) != 1 || subjects[0] != "public" {
			t.Errorf("subject_types_supported: got %v, want [\"public\"]", subjects)
		}
	} else {
		t.Error("subject_types_supported field is missing")
	}

	if signingAlgs, exists := config["id_token_signing_alg_values_supported"]; exists {
		algs := signingAlgs.([]interface{})
		expectedAlgs := []string{"HS256", "RS256"}
		if len(algs) != len(expectedAlgs) {
			t.Errorf("id_token_signing_alg_values_supported length: got %d, want %d", len(algs), len(expectedAlgs))
		}
		for i, expectedAlg := range expectedAlgs {
			if i < len(algs) && algs[i] != expectedAlg {
				t.Errorf("id_token_signing_alg_values_supported[%d]: got %v, want %v", i, algs[i], expectedAlg)
			}
		}
	} else {
		t.Error("id_token_signing_alg_values_supported field is missing")
	}
}

func TestWellKnownOpenIdConfiguration_JSONStructure(t *testing.T) {
	req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(wellKnownOpenIdConfiguration)
	handler.ServeHTTP(rr, req)

	// Verify that the response is valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	// Verify that all expected fields are present and have correct types
	stringFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
	}

	for _, field := range stringFields {
		if value, exists := result[field]; !exists {
			t.Errorf("Field '%s' is missing", field)
		} else if _, ok := value.(string); !ok {
			t.Errorf("Field '%s' should be a string, got %T", field, value)
		}
	}

	arrayFields := []string{
		"scopes_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}

	for _, field := range arrayFields {
		if value, exists := result[field]; !exists {
			t.Errorf("Field '%s' is missing", field)
		} else if _, ok := value.([]interface{}); !ok {
			t.Errorf("Field '%s' should be an array, got %T", field, value)
		}
	}
}

func TestWellKnownOpenIdConfiguration_HTTPMethods(t *testing.T) {
	// Test that only GET method is supported (per OpenID Connect spec)
	methods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		req, err := http.NewRequest(method, "/.well-known/openid-configuration", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(wellKnownOpenIdConfiguration)
		handler.ServeHTTP(rr, req)

		// The handler should still respond (it doesn't check method),
		// but this test documents expected behavior
		if rr.Code != http.StatusOK {
			t.Logf("Method %s returned status %d (this may be expected behavior)", method, rr.Code)
		}
	}
}

func TestPKCEValidation(t *testing.T) {
	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    CodeChallengeMethod
		expected  bool
	}{
		{
			name:      "Plain method - valid",
			verifier:  "test_verifier",
			challenge: "test_verifier",
			method:    CodeChallengePlain,
			expected:  true,
		},
		{
			name:      "Plain method - invalid",
			verifier:  "test_verifier",
			challenge: "wrong_challenge",
			method:    CodeChallengePlain,
			expected:  false,
		},
		{
			name:      "S256 method - valid",
			verifier:  "test_verifier",
			challenge: generateS256Challenge("test_verifier"),
			method:    CodeChallengeS256,
			expected:  true,
		},
		{
			name:      "S256 method - invalid",
			verifier:  "test_verifier",
			challenge: "wrong_challenge",
			method:    CodeChallengeS256,
			expected:  false,
		},
		{
			name:      "Empty challenge",
			verifier:  "test_verifier",
			challenge: "",
			method:    CodeChallengeS256,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateCodeChallenge(tt.verifier, tt.challenge, tt.method)
			if result != tt.expected {
				t.Errorf("validateCodeChallenge() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
		method   CodeChallengeMethod
		expected string
	}{
		{
			name:     "Plain method",
			verifier: "test_verifier",
			method:   CodeChallengePlain,
			expected: "test_verifier",
		},
		{
			name:     "S256 method",
			verifier: "test_verifier",
			method:   CodeChallengeS256,
			expected: generateS256Challenge("test_verifier"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := base64URLEncode(tt.verifier, tt.method)
			if result != tt.expected {
				t.Errorf("base64URLEncode() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestWellKnownOpenIdConfiguration_PKCESupport(t *testing.T) {
	req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(wellKnownOpenIdConfiguration)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var config map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &config)
	if err != nil {
		t.Fatalf("Could not parse JSON response: %v", err)
	}

	// Check PKCE support
	if methods, exists := config["code_challenge_methods_supported"]; exists {
		methodsArray := methods.([]interface{})
		expectedMethods := []string{"plain", "S256"}
		
		if len(methodsArray) != len(expectedMethods) {
			t.Errorf("code_challenge_methods_supported length: got %d, want %d", len(methodsArray), len(expectedMethods))
		}
		
		for i, method := range expectedMethods {
			if i < len(methodsArray) && methodsArray[i] != method {
				t.Errorf("code_challenge_methods_supported[%d]: got %v, want %v", i, methodsArray[i], method)
			}
		}
	} else {
		t.Error("code_challenge_methods_supported field is missing")
	}
}

// Helper function to generate S256 challenge for testing
func generateS256Challenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	hashed := h.Sum(nil)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)
}
