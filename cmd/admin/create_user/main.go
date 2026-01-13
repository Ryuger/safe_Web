package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"safe_web/internal/auth"
)

func main() {
	username := flag.String("username", "", "username to create")
	password := flag.String("password", "", "password to hash")
	flag.Parse()

	if *username == "" || *password == "" {
		log.Fatal("username and password are required")
	}

	hash, err := auth.HashPassword(*password)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}

	fmt.Printf(
		"INSERT INTO users (username, password_hash, is_active, password_changed_at) VALUES ('%s', '%s', true, '%s');\n",
		*username,
		hash,
		time.Now().UTC().Format(time.RFC3339),
	)
}
