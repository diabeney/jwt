package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claims map[string]interface{}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeBase64URL(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

func createSignature(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return encodeBase64URL(h.Sum(nil))
}

func parseToken(token string) (header, Claims, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header{}, nil, "", errors.New("invalid token format")
	}

	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return header{}, nil, "", fmt.Errorf("invalid header encoding: %w", err)
	}

	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return header{}, nil, "", fmt.Errorf("invalid header JSON: %w", err)
}	
	claimsBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return header{}, nil, "", fmt.Errorf("invalid claims encoding: %w", err)
	}

	var c Claims
	if err := json.Unmarshal(claimsBytes, &c); err != nil {
		return header{}, nil, "", fmt.Errorf("invalid claims JSON: %w", err)
	}

	return h, c, parts[2], nil
}

func validateHeader(h header) error {
	if h.Typ != "JWT" || h.Alg != "HS256" {
		return errors.New("unsupported token type or algorithm")
	}
	return nil
}

func validateClaims(claims Claims) error {
	now := time.Now()

	if exp, ok := claims["exp"]; ok {
		expTime, err := parseUnixTime(exp)
		if err != nil {
			return fmt.Errorf("invalid exp claim: %w", err)
		}
		if now.After(expTime) {
			return errors.New("token expired")
		}
	}

	if iat, ok := claims["iat"]; ok {
		iatTime, err := parseUnixTime(iat)
		if err != nil {
			return fmt.Errorf("invalid iat claim: %w", err)
		}
		if now.Before(iatTime) {
			return errors.New("token used before issue time")
		}
	}

	return nil
}

func parseUnixTime(value interface{}) (time.Time, error) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0), nil
	case int64:
		return time.Unix(v, 0), nil
	case int:
		return time.Unix(int64(v), 0), nil
	default:
		return time.Time{}, errors.New("invalid time format")
	}
}


func Decode(token string) (Claims, error) {
	_, c, _, err := parseToken(token);

	if err != nil {
		return nil, errors.New("failed to parse token")
	}

	return c, nil
}

func Sign(claims Claims, secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secret cannot be empty")
	}

	h := header{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payload := Claims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 10).Unix(), // should expire in 10 minutes if not provided.
	}

	for k, v := range claims {
		if k != "iat" { // intentionally not overriding 'issued at' field
			payload[k] = v
		}
	}

	payloadJSON, err := json.Marshal(payload)

	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	encodedHeader := encodeBase64URL(headerJSON)
	encodedPayload := encodeBase64URL(payloadJSON)

	signatureInput := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)

	signature := createSignature(signatureInput, secret)

	return fmt.Sprintf("%s.%s", signatureInput, signature), nil
}

func Verify(token string, secret string) (Claims, error) {

	h, claims, signature, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	if err := validateHeader(h); err != nil {
		return nil, err
	}

	if err := validateClaims(claims); err != nil {
		return nil, err
	}

	parts := strings.Split(token, ".")
	signatureInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
	expectedSignature := createSignature(signatureInput, secret)

	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return nil, errors.New("invalid signature")
	}

	return claims, nil
}
