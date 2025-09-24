package main

import (
	"fmt"
	"log"
	"github.com/diabeney/jwt/cmd/jwt"
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

	obj, err := jwt.Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjbGllbnQtYXBwIiwiY2xpZW50IjoicnV2b28iLCJleHAiOjE3NTg3MTUzODAsImlhdCI6MTc1ODcxNDc4MCwiaXNzIjoiamVkIiwicm9sZSI6ImFkbWluIiwic3ViIjoicGVla2FibyJ9._m4tUlEGtECzOzuHmh0AQSR6d8Kr923myg2Jp97KY1M")

	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	fmt.Println("decoded token: ", obj)

}
