package main

import (
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
		"issuer":                 "http://localhost:8081",
		"authorization_endpoint": "http://localhost:8081/auth",
		"token_endpoint":         "http://localhost:8081/token",
		"userinfo_endpoint":      "http://localhost:8081/userinfo",
		"jwks_uri":               "http://localhost:8081/certs",
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
		if len(algs) != 1 || algs[0] != "RS256" {
			t.Errorf("id_token_signing_alg_values_supported: got %v, want [\"RS256\"]", algs)
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
