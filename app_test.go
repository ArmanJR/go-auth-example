package main

import (
	"bytes"
	"encoding/json"
	"github.com/go-redis/redis"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterHandler(t *testing.T) {
	// Setup
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})

	payload := []byte(`{"username": "testuser", "password": "testpass", "role": "user"}`)
	req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerHandler)

	// Execute
	handler.ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestLoginHandler(t *testing.T) {
	// Setup
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})

	// Setup
	users := make(map[string]User)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	users["testuser"] = User{Username: "testuser", Password: string(hashedPassword), Role: "user"}

	payload := []byte(`{"username": "testuser", "password": "testpass"}`)
	req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginHandler)

	// Execute
	handler.ServeHTTP(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, resp["token"])
}
