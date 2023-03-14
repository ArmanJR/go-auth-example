package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// User represents a registered user
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Email    string `json:"email"`
}

// PasswordReset represents a password reset request
type PasswordReset struct {
	Email string `json:"email"`
}

// JWTClaims represents the claims of a JWT token
type JWTClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// RestrictedAreaPayload represents the needed payload for a request
type RestrictedAreaPayload struct {
	Token string `json:"token"`
}

var redisClient *redis.Client

var (
	JwtSecret     = "sabzi-polo"
	JwtIssuer     = "auth-example"
	RedisAddr     = "redis:6379"
	RedisPassword = ""
)

func main() {
	log.Println("Starting server...")

	redisClient = redis.NewClient(&redis.Options{
		Addr:     RedisAddr,
		Password: RedisPassword,
		DB:       0,
	})

	r := mux.NewRouter()

	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/forgot-password", forgotPasswordHandler).Methods("POST")
	r.HandleFunc("/reset-password", resetPasswordHandler).Methods("POST")
	r.HandleFunc("/restricted-area", restrictedAreaHandler).Methods("POST")

	http.ListenAndServe(":8000", r)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Store user in Redis
	data := fmt.Sprintf("{\"username\": \"%s\", \"password\": \"%s\", \"role\": \"%s\", \"email\": \"%s\"}", user.Username, hashedPassword, user.Role, user.Email)
	err = redisClient.Set(user.Username+":"+user.Email, data, 0).Err() //storing keys as username:email
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Successfully registered"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if user exists
	users, err := redisClient.Keys(user.Username + ":*").Result()
	if len(users) == 0 {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Redis error", http.StatusInternalServerError)
		return
	}
	userCachedStr, err := redisClient.Get(users[0]).Result()
	if err != nil {
		http.Error(w, "Redis error", http.StatusInternalServerError)
		return
	}

	var userCached User
	err = json.Unmarshal([]byte(userCachedStr), &userCached)
	if err != nil {
		http.Error(w, "Failed to parse user data", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(userCached.Password), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	token, err := createToken(userCached.Username, userCached.Role)
	if err != nil {
		http.Error(w, "Failed to create JWT token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
	return
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req PasswordReset

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if user exists
	users, err := redisClient.Keys("*:" + req.Email).Result()
	if len(users) == 0 {
		http.Error(w, "User does not exist", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Redis error", http.StatusInternalServerError)
		return
	}

	// Generate password reset token
	resetToken, err := createToken(req.Email, "reset")
	if err != nil {
		http.Error(w, "Failed to create password reset token", http.StatusInternalServerError)
		return
	}

	// Store password reset token in Redis with expiry of 5 minutes
	err = redisClient.Set(req.Email+":password_reset", resetToken, 5*time.Minute).Err()
	if err != nil {
		http.Error(w, "Failed to store password reset token", http.StatusInternalServerError)
		return
	}

	// Send password reset link to user
	fmt.Fprintf(w, "Password reset link: http://localhost:8000/reset-password?email=%s&token=%s", req.Email, resetToken)
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	resetToken := r.URL.Query().Get("token")

	// Check if email and reset token are valid
	storedToken, err := redisClient.Get(email + ":password_reset").Result()
	if err != nil || storedToken != resetToken {
		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	var user User

	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user.Password = string(hashedPassword)
	data := fmt.Sprintf("{\"username\": \"%s\", \"password\": \"%s\", \"role\": \"%s\", \"email\": \"%s\"}", user.Username, user.Password, user.Role, user.Email)
	err = redisClient.Set(user.Username+user.Email, data, 0).Err() //storing keys as username:email
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete password reset token from Redis
	redisClient.Del(email + ":password_reset")

	w.WriteHeader(http.StatusOK)
}

func restrictedAreaHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the JWT token from the "Authorization" header
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	// Parse and verify the JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the token signing method and secret key
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid token signing method")
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Extract the claims from the JWT token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check the user's role to ensure they have authorization
		if role, ok := claims["role"].(string); ok && (role == "admin" || role == "author") {
			w.Write([]byte("Welcome to the restricted area!"))
			return
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	return
}

func createToken(username, role string) (string, error) {
	claims := &JWTClaims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    JwtIssuer,
			Subject:   "auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(JwtSecret))
}
