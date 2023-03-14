# Auth Example
This is a small example of how to implement authentication & authorization using JWT tokens in a Go web app.

## Build and Run
Three services are available in `docker-compose.yml` file:
- **App**: Go auth web app
- **Redis**: For storing users data
- **Test**: Go tester

By Running `docker-compose up -d` you will start App and Redis, and Test will immediately test the app and exit.

Remember to use VPN while running `docker-compose` to avoid `go mod download` errors.

## App Endpoints
- [POST] `/register`: Register new user
```bash
curl --request POST \
--url http://localhost:8000/register \
--header 'Content-Type: application/json' \
--data '{
    "username": "ordak",
    "password": "quak",
    "role": "admin",
    "email": "a@b.com"
}'
```

- [POST] `/login`: Login and get a JWT token
```bash
curl --request POST \
  --url http://localhost:8000/login \
  --header 'Content-Type: application/json' \
  --data '{
    "username": "ordak",
    "password": "quak"
}'
```

- [POST] `/restricted-area`: Restricted page for checking auth functionality
```bash
curl --request POST \
  --url http://localhost:8000/restricted-area \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im9yZGFrIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNjc4Nzk0MTQ0LCJpYXQiOjE2Nzg3OTA1NDQsImlzcyI6ImF1dGgtZXhhbXBsZSIsInN1YiI6ImF1dGgifQ.BDihoeggHPDBTom_KQwdwRVJxQjVzBnV9Y6rlHsxm_8' \
  --header 'Content-Type: application/json'
```

- [POST] `/forgot-password`: To get a link for password reset
```bash
curl --request POST \
  --url http://localhost:8000/forgot-password \
  --header 'Content-Type: application/json' \
  --data '{
    "email": "a@b.com"
}'
```

- [POST] `/reset-password`: To password reset
```bash
curl --request POST \
  --url 'http://localhost:8000/reset-password?email=a%40b.com&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFAYi5jb20iLCJyb2xlIjoicmVzZXQiLCJleHAiOjE2Nzg3OTQzNzEsImlhdCI6MTY3ODc5MDc3MSwiaXNzIjoiYXV0aC1leGFtcGxlIiwic3ViIjoiYXV0aCJ9._9maQaQDG36NbPHbIIwct7P5DvHLUztdK30Coqj_99g' \
  --header 'Content-Type: application/json' \
  --data '{
	"password": "quak-quak"
}'
```

## Author
- Arman Jafarnezhad