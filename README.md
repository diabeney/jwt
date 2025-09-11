# Minimal JWT Implementation in Go

A minimal, RFC-compliant JWT (JSON Web Token) library written in Go. It supports only HS256 algorithm with basic time-based claim validation.

## Inspiration

This project was inspired by [ThePrimeagen's Boot.dev tutorial](https://www.youtube.com/watch?v=FknTw9bJsXM) on implementing HTTP from scratch using the RFC specifications. As I'm learning Go, I decided to apply the same approach to implement a minimal version of JWT by following the [RFC 7519](https://tools.ietf.org/html/rfc7519) specification.

## Features

- **Minimal by design**: Only supports HS256 (HMAC with SHA-256) algorithm
- **Time-based validation**: Validates `iat` (issued at) and `exp` (expiration) claims
- **RFC 7519 compliant**: Follows JWT specification standards (not everything😂)
- **Simple**: Simple `Sign` and `Verify` functions
- **Security**: Just for learning purposes. Don't use it in any serious work.

## Limitations (By Design)

- Only supports HS256 algorithm (no RSA, ECDSA, or other algorithms)
- Only validates `iat` and `exp` claims (no `nbf`, `iss`, `aud` validation)
- No support for nested JWTs or JWE
- No key rotation support

## Installation

```bash
go get github.com/diabeney/jwt
```

Or if using as a local package:

```go
import "townn/jwt"
```

## Usage

### Basic Example

```go
package main

import (
    "fmt"
    "log"
    "time"
    "townn/jwt"
)

func main() {
    claims := jwt.Claims{
        "role":   "admin",
        "client": "ruvooo",
        "sub":    "",
        "exp":    time.Now().Add(24 * time.Hour).Unix(),
        "iss":    "jed",
        "aud":    "twtrrr",
    }
    
    secret := "your-secret-key"
    
    // Sign token
    token, err := jwt.Sign(claims, secret)
    if err != nil {
        log.Fatalf("Failed to sign token: %v", err)
    }
    
    fmt.Println("Token:", token)
    
    // Verify token
    verifiedClaims, err := jwt.Verify(token, secret)
    if err != nil {
        log.Fatalf("Token verification failed: %v", err)
    }
    
    fmt.Println("Claims:", verifiedClaims)
}
```

### API Reference

#### `jwt.Sign(claims Claims, secret string) (string, error)`

Creates a JWT token with the provided claims and secret.

- **claims**: A map of claims to include in the token
- **secret**: Secret key for HMAC signing
- **Returns**: JWT token string or error

**Note**: The `iat` (issued at) claim is automatically added with the current timestamp.

#### `jwt.Verify(token string, secret string) (Claims, error)`

Verifies a JWT token and returns the claims if valid.

- **token**: JWT token string to verify
- **secret**: Secret key used for verification
- **Returns**: Claims map or error

**Validation performed**:
- Token format (3 parts separated by dots)
- Header algorithm and type (must be HS256 and JWT)
- Signature verification using HMAC-SHA256
- Expiration time (`exp` claim if present)
- Issued at time (`iat` claim if present)

#### `jwt.Claims`

Type alias for `map[string]interface{}` representing JWT claims.

## Implementation Details

### Token Structure

```
header.payload.signature
```

- **Header**: `{"alg":"HS256","typ":"JWT"}` (base64url encoded)
- **Payload**: Claims object (base64url encoded)  
- **Signature**: HMAC-SHA256 of `header.payload` (base64url encoded)

### Security Considerations

- Uses `crypto/hmac` 
- Validates token structure and format before processing
- Uses base64 URL encoding without padding (RFC 7515)

## Testing

```bash
go run main.go
```
## Resources

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

