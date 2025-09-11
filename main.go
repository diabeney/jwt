package main

import (
	"fmt"
	"log"
	"townn/jwt"
)
func main() {
	claims := jwt.Claims{
		"role":   "admin",
		"client": "ruvoo",
		"sub":    "peekabo",
		"iss":    "jed",
		"aud":    "client-app",
	}

	secret := "my-top-secret-is-here"

	token, err := jwt.Sign(claims, secret)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	fmt.Println("Generated token:")
	fmt.Println(token)

	verifiedClaims, err := jwt.Verify(token, secret)
	if err != nil {
		fmt.Printf("Token verification failed: %v\n", err)
		return
	}

	fmt.Printf("token is valid: %v", verifiedClaims)
}
