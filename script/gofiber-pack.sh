#!/bin/bash
# description: fast init GoFiber project with full module with JWT and SSO from raw frontend base (React, Vue, Angular, Svelte, Vite, ...)
# example: curl -fsSL https://init.jefripunza.com/gofiber-pack.sh -o gofiber-pack.sh && bash gofiber-pack.sh my-project-name

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status

DATE=$(date +"%Y%m%d-%H%M%S")
CURRENT_USER=$USER
rm -rf gofiber-pack.sh

### ========================================================================== ###
###                               INITIALIZATION                               ###
### ========================================================================== ###

echo "Initializing..."

### check apakah di command ada "bun", kalau belum ada di install
if ! command -v bun &> /dev/null; then
    echo "bun not found, installing..."
    curl -fsSL https://bun.sh/install | bash
fi

# check apakah di command ada "yarn", kalau belum ada di install
if ! command -v yarn &> /dev/null; then
    echo "yarn not found, installing..."
    bun install -g yarn
fi

# check apakah di command ada "pnpm", kalau belum ada di install
if ! command -v pnpm &> /dev/null; then
    echo "pnpm not found, installing..."
    bun install -g pnpm
fi

# check apakah di command ada "go", kalau belum ada di install
if ! command -v go &> /dev/null; then
    echo "go not found, please install go first"
    exit 1
fi

### ========================================================================== ###
###                             CREATE PROJECT                                 ###
### ========================================================================== ###

echo "Creating project..."

if [ -z "$1" ]; then
    echo "Please provide a project name"
    exit 1
fi
project_name=$1
go mod init $project_name

### ========================================================================== ###
###                               GENERATION                                   ###
### ========================================================================== ###

echo "Generating files..."

# Function to create a new file or replace an existing one
generate() {
    local file_path="$1"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$file_path")"
    
    # Check if file exists
    if [ -f "$file_path" ]; then
        echo "Replacing existing file: $file_path"
    else
        echo "Creating new file: $file_path"
    fi
    
    # The content will be provided via heredoc from the caller
    cat > "$file_path"
    echo "✓ File operation completed: $file_path"
}








## >> Root

# create .env.example
generate "./.env.example" << EOL
# Server
ENVIRONMENT=
SERVER_NAME=
SERVER_PORT=
SECRET_KEY=
SERVER_FRONTEND_HOSTNAME=

# SSO
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

MONGO_URL=

# SAWANG KEUANGAN
SAWANG_KEUANGAN_URL=
SAWANG_KEUANGAN_X_ENVIRONMENT=
SAWANG_KEUANGAN_X_API_KEY=
EOL

# create Dockerfile
generate "./Dockerfile" << EOL
# Stage 1: 🛠️ Build ReactJS app using Bun.js
FROM oven/bun:latest AS fe-builder
LABEL org.opencontainers.image.authors="jefriherditriyanto@gmail.com"

WORKDIR /react-build

#-> 🌊 Copy package.json, bun.lockb, and source code
COPY . .

#-> 🌊 Install dependencies and build the app
RUN bun install

# # Start manually
# CMD ["bun", "run", "preview"]

#-> ⚒️ Build the app
RUN bun run build








# Stage 2: 🛠️ Build GoFiber backend using Go
FROM golang:latest AS be-builder

#-> 🌊 Setup Environment
# ENV GOPATH /go
# ENV PATH $PATH:$GOPATH/bin
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO=0

#-> 🌊 Install Require
# RUN apk add --no-cache \
#     gcc \
#     musl-dev \
#     tzdata

WORKDIR /app
RUN mkdir ./dist
COPY . .
COPY --from=fe-builder /react-build/dist/ ./dist

#-> 🌊 Install Golang Module
RUN go mod download

# 💯 Configuration
RUN sed -i 's#127.0.0.1:#:#g' /app/server/http/server.http.go
# RUN for file in /app/server/env/*; do \
#     sed -i 's#localhost#host.docker.internal#g' "$file"; \
#     done

#-> ⚒️ Build App
RUN go build -o ./run









# Stage 3: 🚀 Finishing
FROM ubuntu:latest AS runner
WORKDIR /app

#-> 🌊 Install ffmpeg along with the other tools
RUN apt-get update && apt-get install -y openssl curl nano ffmpeg

COPY --from=be-builder /app/run /app/run

# 💯 Last Configuration
# COPY --from=be-builder /build/.env    /app/.env
# RUN sed -i 's#localhost#host.docker.internal#g' .env

RUN chmod +x ./run

EXPOSE 3000

ENTRYPOINT ["/app/run"]
CMD ["run"]
EOL

# create main.go
generate "./main.go" << EOL
package main

import (
	"embed"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"${project_name}/server"
	"${project_name}/server/auth"
	"${project_name}/server/connection"
	"${project_name}/server/util"
)

//go:embed dist/*
var embeddedFiles embed.FS

func main() {
	// var err error

	// ---------------------------------

	Env := util.Env{}
	Env.Load()

	// ---------------------------------

	Goth := auth.Goth{}
	Goth.Init()

	// ---------------------------------

	MongoDB := connection.MongoDB{}
	MongoDB.Connect()

	// ---------------------------------

	server.Run(embeddedFiles)

	// ---------------------------------

	// Listen to Ctrl+C (you can also do something else that prevents the program from exiting)
	time.Sleep(3 * time.Second)
	log.Println("🚦 Listen to Ctrl+C ...")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

}
EOL







# >> Server (Auth)

# create server/auth/goth.auth.go
generate "./server/auth/goth.auth.go" << EOL
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"${project_name}/server/env"
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
)

type Goth struct{}

func (ref Goth) Init() {
	google_client_id := env.GetGoogleClientId()
	google_client_secret := env.GetGoogleClientSecret()

	// fmt.Printf("google_client_id: %s\n", google_client_id)
	// fmt.Printf("google_client_secret: %s\n", google_client_secret)

	callbackURL := fmt.Sprintf("%s/sso", env.GetServerFrontendHostname())

	goth.UseProviders(
		google.New(google_client_id, google_client_secret, callbackURL, "email", "profile"),
	)
}

func (ref Goth) GetAuthURL(ctx *fiber.Ctx) (string, error) {
	providerName, err := getProviderName(ctx)
	if err != nil {
		return "", err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	sess, err := provider.BeginAuth(setState(ctx))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	return url, err
}

// func (ref Goth) CompleteUserAuth(ctx *fiber.Ctx) (goth.User, error) {
// 	providerName, err := getProviderName(ctx)
// 	if err != nil {
// 		return goth.User{}, err
// 	}
// 	fmt.Printf("providerName: %s\n", providerName)

// 	provider, err := goth.GetProvider(providerName)
// 	if err != nil {
// 		return goth.User{}, err
// 	}
// 	fmt.Printf("provider: %s\n", provider)

// 	sess, err := provider.UnmarshalSession(setState(ctx))
// 	if err != nil {
// 		return goth.User{}, err
// 	}
// 	fmt.Printf("sess: %s\n", sess)

// 	gu, err := provider.FetchUser(sess)
// 	return gu, err
// }

// Custom Params type that implements goth.Params
type CustomParams map[string]string

// Implement the Get method required by the goth.Params interface
func (p CustomParams) Get(key string) string {
	return p[key]
}

func (ref Goth) CompleteUserAuth(ctx *fiber.Ctx) (goth.User, error) {
	providerName, err := getProviderName(ctx)
	if err != nil {
		return goth.User{}, err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}

	state := ctx.Query("state")
	fmt.Printf("Received state: %s\n", state)

	// Tukar kode otorisasi dengan token
	code := ctx.Query("code")
	if code == "" {
		return goth.User{}, errors.New("no code in request")
	}

	// Ambil sesi dari \'code\' (tanpa UnmarshalSession)
	sess, err := provider.BeginAuth(state)
	if err != nil {
		return goth.User{}, fmt.Errorf("failed to start auth session: %w", err)
	}

	// Authorize session dengan code dari query
	params := CustomParams{"code": code}
	_, err = sess.Authorize(provider, params)
	if err != nil {
		return goth.User{}, fmt.Errorf("failed to authorize session: %w", err)
	}

	// Ambil informasi pengguna setelah token diterima
	user, err := provider.FetchUser(sess)
	if err != nil {
		return goth.User{}, fmt.Errorf("failed to fetch user: %w", err)
	}

	return user, nil
}

// functions

func getProviderName(ctx *fiber.Ctx) (string, error) {
	// try to get it from the url param ":provider"
	provider_name := ctx.Params("provider")
	if provider_name != "" {
		return provider_name, nil
	}

	// As a fallback, loop over the used providers, if we already have a valid session for any provider (ie. user has already begun authentication with a provider), then return that provider name
	providers := goth.GetProviders()
	for _, provider := range providers {
		if p := provider.Name(); p != "" {
			if provider_name == provider.Name() {
				return p, nil
			}
		}
	}

	// if not found then return an empty string with the corresponding error
	return "", errors.New("you must select a provider")
}

func setState(ctx *fiber.Ctx) string {
	state := ctx.Query("state")
	if len(state) > 0 {
		return state
	}

	// If a state query param is not passed in, generate a random
	// base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	//
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("gothic: source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}
EOL






# >> Server (Connection)

# create server/connection/mongodb.connection.go
generate "./server/connection/mongodb.connection.go" << EOL
package connection

import (
	"context"
	"fmt"
	"log"

	"${project_name}/server/env"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct{}

var mongoDbConnected = false

func (ref MongoDB) Connect() (*mongo.Client, context.Context, error) {
	ctx := context.Background()
	uri := env.GetMongoUrl()

	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, ctx, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, ctx, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	if !mongoDbConnected {
		log.Println("✅ MongoDB Connected")
		mongoDbConnected = true
	}
	return client, ctx, nil
}

type MongoDbIndex struct {
	Name   string 'json:"name"'
	Unique bool   'json:"unique"'
	Keys   bson.M 'json:"keys"'
}

func (ref MongoDB) CreateIndex(ctx context.Context, database *mongo.Database, collectionName string, listIndex []MongoDbIndex) error {
	collection := database.Collection(collectionName)
	for _, index := range listIndex {
		opt := options.Index()
		opt = opt.SetName(index.Name)
		if index.Unique {
			opt = opt.SetUnique(index.Unique)
		}
		_, err := collection.Indexes().CreateOne(
			ctx,
			mongo.IndexModel{
				Keys:    index.Keys,
				Options: opt,
			},
		)
		if err != nil {
			log.Fatalf("Error on CreateIndex: %v", err)
			return err
		}
	}
	return nil
}
EOL







## >> Server (DTO)

# create server/dto/auth.dto.go
generate "./server/dto/auth.dto.go" << EOL
package dto

import "go.mongodb.org/mongo-driver/bson/primitive"

type AuthEncryptBody struct {
	Text string \`json:"text"\`
}
type AuthDecryptBody struct {
	EncryptedText string \`json:"encrypted_text"\`
}

type AuthTokenValidation struct {
	ID       *primitive.ObjectID \`bson:"_id,omitempty" json:"_id,omitempty"\`
	Email    *string             \`bson:"email,omitempty" json:"email,omitempty"\`         // SSO
	RoleCode *string             \`bson:"role_code,omitempty" json:"role_code,omitempty"\` // admin,
	Balance  *int64              \`bson:"balance,omitempty" json:"balance,omitempty"\`     // default: 0

	// Info
	Name      string \`bson:"name" json:"name"\`
	Address   string \`bson:"address" json:"address"\`

	Whatsapp      string  \`bson:"whatsapp" json:"whatsapp"\`

	// Settings
	IsDarkMode *bool \`bson:"is_dark_mode,omitempty" json:"is_dark_mode,omitempty"\` // default: false
	IsActive   *bool \`bson:"is_active,omitempty" json:"is_active,omitempty"\`       // default: true
}
EOL

# create server/dto/callback.dto.go
generate "./server/dto/callback.dto.go" << EOL
package dto

type CallbackUpdateCustomer struct {
	Email string \`json:"email"\`
	Name  string \`json:"name"\`
}
type CallbackUpdateBody struct {
	TrxID         string                 \`json:"trx_id"\`
	Customer      CallbackUpdateCustomer \`json:"customer"\`
	PaymentAt     string                 \`json:"payment_at"\`
	PaymentMethod string                 \`json:"payment_method"\`
	Status        string                 \`json:"status"\`
}
EOL

# create server/dto/topup.dto.go
generate "./server/dto/topup.dto.go" << EOL
package dto

type TopupCreateBody struct {
	Amount int \`json:"amount"\`
}
EOL

# create server/dto/transaction.dto.go
generate "./server/dto/transaction.dto.go" << EOL
package dto

type TransactionActionBody struct {
	Status string \`json:"status" validate:"required,oneof=approved rejected"\`
	Amount int64  \`json:"amount"\`
	Note   string \`json:"note,omitempty"\`
}
EOL

# create server/dto/user.dto.go
generate "./server/dto/user.dto.go" << EOL
package dto

type UserEditBody struct {
	// Info
	Name    string \`json:"name" validate:"required,min=3"\`
	Address string \`json:"address" validate:"required"\`

	Whatsapp string \`json:"whatsapp" validate:"required,e164"\` // E.164 format
}
EOL









# >> Server (Enigma)

# create server/enigma/general.enigma.go
generate "./server/enigma/general.enigma.go" << EOL
package enigma

import "${project_name}/server/util"

func General(key string) []util.EnigmaSchema {
	return []util.EnigmaSchema{
		{
			Method: util.AES,
			Key:    func() string { return key }, // Layer 1: AES with original key
		},
		{
			Method: util.AES,
			Key:    func() string { return util.ReverseStrings(key) }, // Layer 2: AES with reversed key
		},
		{
			Method: util.AES,
			Key:    func() string { return key[:len(key)/2] }, // Layer 3: AES with first half of the key
		},
		{
			Method: util.AES,
			Key:    func() string { return key[len(key)/2:] }, // Layer 4: AES with second half of the key
		},
		{
			Method: util.Base64, // Layer 5: Base64 Encoding
		},
	}
}
EOL

# create server/enigma/user_password.enigma.go
generate "./server/enigma/user_password.enigma.go" << EOL
package enigma

import "${project_name}/server/util"

func UserPassword(key string) []util.EnigmaSchema {
	return []util.EnigmaSchema{
		{
			Method: util.AES,
			Key:    func() string { return key }, // Layer 1: AES with original key
		},
		{
			Method: util.AES,
			Key:    func() string { return key[len(key)/2:] }, // Layer 2: AES with second half of the key
		},
		{
			Method: util.AES,
			Key:    func() string { return util.ReverseStrings(key) }, // Layer 3: AES with reversed key
		},
		{
			Method: util.AES,
			Key:    func() string { return key[:len(key)/2] }, // Layer 4: AES with first half of the key
		},
		{
			Method: util.Base64, // Layer 5: Base64 Encoding
		},
	}
}
EOL








# >> Server (Env)

# create server/env/google.env.go
generate "./server/env/google.env.go" << EOL
package env

import "os"

func GetGoogleClientId() string {
	value := os.Getenv("GOOGLE_CLIENT_ID")
	if value == "" {
		value = ""
	}
	return value
}

func GetGoogleClientSecret() string {
	value := os.Getenv("GOOGLE_CLIENT_SECRET")
	if value == "" {
		value = ""
	}
	return value
}
EOL

# create server/env/mongodb.env.go
generate "./server/env/mongodb.env.go" << EOL
package env

import "os"

func GetMongoUrl() string {
	value := os.Getenv("MONGO_URL")
	if value == "" {
		value = "mongodb://localhost:27017"
	}
	return value
}
EOL

# create server/env/sawang.env.go
generate "./server/env/sawang.env.go" << EOL
package env

import "os"

func GetSawangKeuanganUrl() string {
	value := os.Getenv("SAWANG_KEUANGAN_URL")
	if value == "" {
		panic("SAWANG_KEUANGAN_URL is not set")
	}
	return value
}

func GetSawangKeuanganXEnvironment() string {
	value := os.Getenv("SAWANG_KEUANGAN_X_ENVIRONMENT")
	if value == "" {
		value = "sandbox"
	}
	return value
}

func GetSawangKeuanganXApiKey() string {
	value := os.Getenv("SAWANG_KEUANGAN_X_API_KEY")
	if value == "" {
		value = ""
	}
	return value
}
EOL

# create server/env/server.env.go
generate "./server/env/server.env.go" << EOL
package env

import (
	"os"
)

func GetEnvironment() string {
	value := os.Getenv("ENVIRONMENT")
	if value == "" {
		value = "sandbox"
	}
	return value
}

func GetServerName() string {
	value := os.Getenv("SERVER_NAME")
	if value == "" {
		value = "P34C3_KHYREIN"
	}
	return value
}

func GetServerPort() string {
	value := os.Getenv("SERVER_PORT")
	if value == "" {
		value = "3000"
	}
	return value
}

func GetSecretKey() string {
	value := os.Getenv("SECRET_KEY")
	if value == "" {
		value = "your_secret_key"
	}
	return value
}

func GetServerFrontendHostname() string {
	value := os.Getenv("SERVER_FRONTEND_HOSTNAME")
	if value == "" {
		value = "http://localhost:5173"
	}
	return value
}
EOL

# create server/env/system.env.go
generate "./server/env/system.env.go" << EOL
package env

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func GetAll() string {
	envVars := os.Environ()
	for _, envVar := range envVars {
		pair := strings.SplitN(envVar, "=", 2)
		if len(pair) == 2 {
			key := pair[0]
			value := pair[1]
			fmt.Printf("%s: %s\n", key, value)
		}
	}
	return strings.Join(envVars, "\n")
}

func GetLocalIP() (string, error) {
	// Try to get all interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range interfaces {
		// Get addresses associated with each interface
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			// Check if the address is an IP address
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip loopback addresses
			if ip == nil || ip.IsLoopback() {
				continue
			}

			// Only consider IPv4 addresses
			if ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no local IP address found")
}

func GetPwd() string {
	pwd, _ := os.Getwd()
	return pwd
}

func GetComputerName() string {
	return os.Getenv("COMPUTERNAME")
}

func GetHostname() string {
	return os.Getenv("HOSTNAME")
}

func GetOS() string {
	return os.Getenv("OS")
}

func GetUsername() string {
	return os.Getenv("USERNAME")
}

func GetArchitecture() string {
	return os.Getenv("MSYSTEM_CARCH")
}

func GetProcessor() string {
	return os.Getenv("NUMBER_OF_PROCESSORS")
}
EOL






# >> Server (HTTP)

# create server/http/module.http.go
generate "./server/http/module.http.go" << EOL
package http

import (
	"${project_name}/server/module"

	"github.com/gofiber/fiber/v2"
)

func Module(app *fiber.App) {
	api := app.Group("/api")

	// --------------------------
	// --------------------------

	Example := module.Example{}
	Example.Route(api)

	Content := module.Content{}
	Content.Route(api)

	// --------------------------

	Auth := module.Auth{}
	Auth.Route(api)

	User := module.User{}
	User.Route(api)

	Transaction := module.Transaction{}
	Transaction.Route(api)

	Topup := module.Topup{}
	Topup.Route(api)

	Callback := module.Callback{}
	Callback.Route(api)

	// --------------------------
	// --------------------------

}
EOL

# create server/http/server.http.go
generate "./server/http/server.http.go" << EOL
package http

import (
	"embed"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"${project_name}/server/env"
	"${project_name}/server/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

func Server(embeddedFiles embed.FS) *fiber.App {
	var err error

	port := env.GetServerPort()
	server_name := env.GetServerName()

	app := fiber.New(fiber.Config{
		ServerHeader:          server_name,
		DisableStartupMessage: true,
		CaseSensitive:         true,
		BodyLimit:             10 * 1024 * 1024, // 10 MB / max file size
	})

	app.Use(helmet.New())
	app.Use(cors.New(cors.Config{
		AllowMethods:  "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		ExposeHeaders: "Content-Type,Authorization,Accept,X-Browser-ID",
		AllowOrigins:  "*",
	}))
	app.Use(requestid.New())
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

	staticFiles, _ := fs.Sub(embeddedFiles, "dist")
	fileServer := http.FS(staticFiles)
	app.Use("*", func(c *fiber.Ctx) error {
		reqPath := c.Path()

		if strings.HasPrefix(reqPath, "/api") || strings.HasPrefix(reqPath, "/papers") || strings.HasPrefix(reqPath, "/icon") || strings.HasPrefix(reqPath, "/file") || strings.HasPrefix(reqPath, "/ws") {
			return c.Next()
		}

		if reqPath == "/" {
			reqPath = "/index.html"
		}

		file, err := fileServer.Open(reqPath)
		if err != nil {
			return c.SendStatus(fiber.StatusNotFound)
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		// Determine the content type
		ext := filepath.Ext(reqPath)
		mimeType := mime.TypeByExtension(ext)
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		c.Type(ext)
		c.Response().Header.Set("Content-Type", mimeType)

		return c.SendStream(file, int(fileInfo.Size()))
	})

	// Route to serve static files from ./uploads
	app.Get("/file/*", func(c *fiber.Ctx) error {
		// Get the wildcard path after /file/
		relativePath := c.Params("*")

		// Clean and construct the full file path
		filePath := filepath.Join("uploads", filepath.Clean(relativePath))

		// Check if the file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"message": "file not found!",
			})
		}

		if strings.Contains(c.Get("referer"), "localhost:5173") {
			c.Set("Cross-Origin-Resource-Policy", "cross-origin")
			c.Set("Access-Control-Allow-Origin", "http://localhost:5173")
		}

		// Serve the file
		return c.SendFile(filePath)
	})

	app.Use(logger.New())

	// error handling
	app.Use(middleware.ErrorHandler())
	Module(app) // /api/*
	app.Use("*", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "endpoint not found!",
		})
	})

	log.Printf("✅ Server \"%s\" started on port http://localhost:%s\n", server_name, port)
	if err = app.Listen("127.0.0.1:" + port); err != nil {
		log.Fatalln("error start server:", err)
	}

	return app
}
EOL






# >> Server (Middleware)

# create server/middleware/error_handle.middleware.go
generate "./server/middleware/error_handle.middleware.go" << EOL
package middleware

import (
	"fmt"
	"${project_name}/server/env"
	"runtime/debug"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func filterStackTrace(trace string) string {
	lines := strings.Split(trace, "\n")
	var filteredLines []string

	for _, line := range lines {
		if !strings.Contains(line, "go/pkg/") && !strings.Contains(line, "Go/src/") && !strings.Contains(line, "github.com/") && !strings.Contains(line, "error_handle.middleware.go") {
			filteredLines = append(filteredLines, line)
		}
	}

	return strings.Join(filteredLines, "\n")
}

// Error handling middleware
func ErrorHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				stackBytes := debug.Stack()
				trace := filterStackTrace(string(stackBytes))
				error_message := fmt.Sprintf("FROM: %s\nRecovered from panic: %v\nStack Trace: %s", env.GetServerName(), r, trace)
				fmt.Println(error_message)
				// if len(error_message) > 1000 {
				// 	error_message = error_message[:1000] // Potong ke 1000 karakter
				// }
				// options := util.RestOptions{
				// 	Method: "POST",
				// 	URL:    "https://remoteworker.id/api/bot/discord/v1/send-message/channel/rwid-server-error",
				// 	Body: map[string]any{
				// 		"message": error_message,
				// 	},
				// }
				// _, restErr := util.RestHit[any](options)
				// if restErr.Message != "" {
				// 	fmt.Println("Error Message:", restErr)
				// }
				// if restErr.Response != "" {
				// 	fmt.Println("Error Response:", restErr)
				// }
				// Kirimkan respon error ke client
				c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"message": "Internal Server Error",
				})
				return
			}
		}()
		return c.Next()
	}
}
EOL

# create server/middleware/role_access.middleware.go
generate "./server/middleware/role_access.middleware.go" << EOL
package middleware

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

func RoleAccess(allowedRoles []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := c.Locals("claims").(jwt.MapClaims)
		role_code := claims["role_code"].(string)
		allowed := false
		for _, role := range allowedRoles {
			// fmt.Printf("Role: %s, Role Code: %s\n", role, role_code)
			if role == role_code {
				allowed = true
				break
			}
		}
		if allowed {
			return c.Next()
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"message": fmt.Sprintf("Role %s cannot access", role_code),
		})
	}
}
EOL

# create server/middleware/use_token.middleware.go
generate "./server/middleware/use_token.middleware.go" << EOL
package middleware

import (
	"fmt"
	"${project_name}/server/connection"
	"${project_name}/server/model"
	"${project_name}/server/util"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func UseToken(c *fiber.Ctx) error {
	// device_id := c.Get("X-Device-ID")

	authHeader := c.Get("Authorization")
	if authHeader == "" {
		fmt.Println("=========== 1 err: Bearer token is required")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Bearer token is required",
		})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		fmt.Println("=========== 2 err: Invalid Authorization header format")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid Authorization header format",
		})
	}

	tokenString := parts[1]
	// fmt.Printf("tokenString: %s\n", tokenString)

	JWT := util.JWT{}
	claims, err := JWT.Validate(tokenString)
	if err != nil {
		fmt.Printf("=========== 3 err: %s\n", err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid token",
		})
	}

	email := claims["email"].(string)
	jti := claims["jti"].(string)
	// fmt.Printf("claims: %+v\n", claims)
	// fmt.Printf("email: %s\n", email)
	// fmt.Printf("jti: %s\n", jti)

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	_, err = model.RevokeFindOne(ctx, client, email, jti)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	user, err := model.UserGetByEmail(ctx, client, email)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	// Add claims to context
	c.Locals("claims", claims)
	c.Locals("user", *user)
	c.Locals("email", email)
	c.Locals("jti", jti)

	return c.Next()
}
EOL








# >> Server (Model)

# create server/model/dashboard.model.go
generate "./server/model/dashboard.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/connection"
	"${project_name}/server/variable"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Dashboard struct {
	ID     *primitive.ObjectID \'bson:"_id,omitempty" json:"_id,omitempty"\'
	UserID *primitive.ObjectID \'bson:"user_id,omitempty" json:"user_id,omitempty"\'

	// pointer
	Year  *int \'bson:"year,omitempty" json:"year,omitempty"\'
	Month *int \'bson:"month,omitempty" json:"month,omitempty"\'
	Day   *int \'bson:"day,omitempty" json:"day,omitempty"\'

	// value
	BalanceAvailable *int \'bson:"balance_available,omitempty" json:"balance_available,omitempty"\'
	TotalPayment     *int \'bson:"total_payment,omitempty" json:"total_payment,omitempty"\'
	PendingPayment   *int \'bson:"pending_payment,omitempty" json:"pending_payment,omitempty"\'

	// recap data
	Transactions *[]Transaction \'bson:"transactions,omitempty" json:"transactions,omitempty"\'
}

func DashboardMigrate(ctx context.Context, client *mongo.Client) {
	MongoDB := connection.MongoDB{}
	MongoDB.CreateIndex(ctx, client.Database(variable.WarehouseDatabase), variable.DashboardsCollection, []connection.MongoDbIndex{
		// with user
		{
			Name: "search_user_id",
			Keys: bson.M{"user_id": 1},
		},
		{
			Name: "search_user_id_year",
			Keys: bson.M{"user_id": 1, "year": 1},
		},
		{
			Name: "search_user_id_month",
			Keys: bson.M{"user_id": 1, "month": 1},
		},
		{
			Name: "search_user_id_day",
			Keys: bson.M{"user_id": 1, "day": 1},
		},
		{
			Name: "search_user_id_date",
			Keys: bson.M{"user_id": 1, "year": 1, "month": 1, "day": 1},
		},

		// without user
		{
			Name: "search_year",
			Keys: bson.M{"year": 1},
		},
		{
			Name: "search_month",
			Keys: bson.M{"month": 1},
		},
		{
			Name: "search_day",
			Keys: bson.M{"day": 1},
		},
		{
			Name: "search_date",
			Keys: bson.M{"year": 1, "month": 1, "day": 1},
		},
	})
}
EOL

# create server/model/device.model.go
generate "./server/model/device.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/connection"
	"${project_name}/server/variable"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Device struct {
	ID            *primitive.ObjectID \'bson:"_id,omitempty" json:"_id,omitempty"\'
	FingerprintID string              \'bson:"fingerprint_id" json:"fingerprint_id"\'
	UserAgent     string              \'bson:"user_agent" json:"user_agent"\'
	Emails        []string            \'bson:"emails" json:"emails"\'

	IsBlocked bool               \'bson:"is_blocked" json:"is_blocked"\'
	CreatedAt primitive.DateTime \'bson:"created_at" json:"created_at"\'
}

func DeviceMigrate(ctx context.Context, client *mongo.Client) {
	MongoDB := connection.MongoDB{}
	MongoDB.CreateIndex(ctx, client.Database(variable.AuthDatabase), variable.DevicesCollection, []connection.MongoDbIndex{
		{
			Name:   "fingerprint_id_unique",
			Unique: true,
			Keys:   bson.M{"fingerprint_id": 1},
		},
	})
}

func DeviceInsertIfNotExist(ctx context.Context, client *mongo.Client, email string, fingerprintId string, userAgent string) error {
	database := client.Database(variable.AuthDatabase)

	deviceCollection := database.Collection(variable.DevicesCollection)

	// check if device already exists
	exist := Device{}
	err := deviceCollection.FindOne(ctx, bson.M{
		"fingerprint_id": fingerprintId,
	}).Decode(&exist)
	isExist := true
	if err != nil {
		if err == mongo.ErrNoDocuments {
			isExist = false
		} else {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}

	if !isExist {
		now := primitive.NewDateTimeFromTime(time.Now())
		_, err = deviceCollection.InsertOne(ctx, Device{
			FingerprintID: fingerprintId,
			UserAgent:     userAgent,
			Emails:        []string{email},
			CreatedAt:     now,
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	} else {
		emails := exist.Emails
		for _, e := range emails {
			if e == email {
				return nil
			}
		}
		emails = append(emails, email)
		_, err = deviceCollection.UpdateOne(ctx, bson.M{
			"_id": exist.ID,
		}, bson.M{
			"$set": bson.M{
				"emails": emails,
			},
		})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}

	return nil
}
EOL

# create server/model/login_history.model.go
generate "./server/model/login_history.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/variable"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// -> main collection
type LoginHistory struct {
	ID    *primitive.ObjectID \'json:"_id,omitempty" bson:"_id,omitempty"\'
	Email *string             \'json:"email,omitempty" bson:"email,omitempty"\'

	JwtID *string \'json:"jti,omitempty" bson:"jti,omitempty"\'

	UserAgent *string \'json:"user_agent,omitempty" bson:"user_agent,omitempty"\'
	IpAddress *string \'json:"ip_address,omitempty" bson:"ip_address,omitempty"\'
	DeviceID  *string \'json:"device_id,omitempty" bson:"device_id,omitempty"\'

	LoginAt   *primitive.DateTime \'json:"login_at,omitempty" bson:"login_at,omitempty"\'
	ExpiredAt *primitive.DateTime \'json:"expired_at,omitempty" bson:"expired_at,omitempty"\'
}

func LoginHistoryInsert(ctx context.Context, client *mongo.Client, loginHistory LoginHistory) error {
	database := client.Database(variable.AuthDatabase)

	loginHistoryCollection := database.Collection(variable.LoginHistoriesCollection)

	_, err := loginHistoryCollection.InsertOne(ctx, loginHistory)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return nil
}

func LoginHistoryAll(ctx context.Context, client *mongo.Client, email string) ([]LoginHistory, error) {
	var loginHistories []LoginHistory

	database := client.Database(variable.AuthDatabase)

	loginHistoryCollection := database.Collection(variable.LoginHistoriesCollection)

	cursor, err := loginHistoryCollection.Find(ctx, bson.M{
		"email": email,
	})
	if err != nil {
		return loginHistories, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if err = cursor.All(ctx, &loginHistories); err != nil {
		return loginHistories, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return loginHistories, nil
}
EOL

# create server/model/notification.model.go
generate "./server/model/notification.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/connection"
	"${project_name}/server/variable"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Notification struct {
	ID     *primitive.ObjectID \'bson:"_id,omitempty" json:"_id,omitempty"\'
	UserID *primitive.ObjectID \'bson:"user_id,omitempty" json:"user_id,omitempty"\'

	ContentLabel *string \'bson:"content_label,omitempty" json:"content_label,omitempty"\' // mini for list notification
	ContentBody  *string \'bson:"content_body,omitempty" json:"content_body,omitempty"\'   // for body email (html)

	IsSended        *bool   \'bson:"is_sended,omitempty" json:"is_sended,omitempty"\'         // default: false
	IsSendError     *bool   \'bson:"is_send_error,omitempty" json:"is_send_error,omitempty"\' // default: false
	SendErrorReason *string \'bson:"send_error_reason,omitempty" json:"send_error_reason,omitempty"\'

	SendedAt  *time.Time \'bson:"sended_at,omitempty" json:"sended_at,omitempty"\'
	CreatedAt *time.Time \'bson:"created_at,omitempty" json:"created_at,omitempty"\'
}

func NotificationMigrate(ctx context.Context, client *mongo.Client) {
	MongoDB := connection.MongoDB{}
	MongoDB.CreateIndex(ctx, client.Database(variable.NotificationDatabase), variable.NotificationsCollection, []connection.MongoDbIndex{
		{
			Name: "search_user_id",
			Keys: bson.M{"user_id": 1},
		}, {
			Name: "search_user_id_is_sended",
			Keys: bson.M{"user_id": 1, "is_sended": 1},
		},
	})
}
EOL

# create server/model/revoke.model.go
generate "./server/model/revoke.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/connection"
	"${project_name}/server/variable"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// -> main collection
type Revoke struct {
	ID *primitive.ObjectID \'json:"_id,omitempty" bson:"_id,omitempty"\'

	Email *string \'json:"email,omitempty"  bson:"email,omitempty"\'
	JwtID *string \'json:"jti,omitempty"    bson:"jti,omitempty"\'

	ExpiredAt *primitive.DateTime \'json:"expired_at,omitempty"  bson:"expired_at,omitempty"\'
	LoginAt   *primitive.DateTime \'json:"login_at,omitempty"    bson:"login_at,omitempty"\'
}

func RevokeMigrate(ctx context.Context, client *mongo.Client) {
	MongoDB := connection.MongoDB{}
	MongoDB.CreateIndex(ctx, client.Database(variable.AuthDatabase), variable.RevokesCollection, []connection.MongoDbIndex{
		{
			Name:   "jti_unique",
			Unique: true,
			Keys:   bson.M{"jti": 1},
		},
		{
			Name: "search_email",
			Keys: bson.M{"email": 1},
		},
	})
}

func RevokeFindOne(ctx context.Context, client *mongo.Client, email string, jti string) (*Revoke, error) {
	database := client.Database(variable.AuthDatabase)

	revokeCollection := database.Collection(variable.RevokesCollection)

	exist := Revoke{}
	err := revokeCollection.FindOne(ctx, bson.M{
		"email": email,
		"jti":   jti,
	}).Decode(&exist)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fiber.NewError(fiber.StatusNotFound, "token not found")
		} else {
			return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}

	return &exist, nil
}

func RevokeInsert(ctx context.Context, client *mongo.Client, revoke Revoke) error {
	database := client.Database(variable.AuthDatabase)

	revokeCollection := database.Collection(variable.RevokesCollection)

	now := primitive.NewDateTimeFromTime(time.Now())
	revoke.LoginAt = &now

	_, err := revokeCollection.InsertOne(ctx, revoke)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return nil
}

func RevokeCount(ctx context.Context, client *mongo.Client, email string) (int64, error) {
	database := client.Database(variable.AuthDatabase)
	defer database.Client().Disconnect(ctx)

	revokeCollection := database.Collection(variable.RevokesCollection)

	count, err := revokeCollection.CountDocuments(ctx, bson.M{
		"email": email,
	})
	if err != nil {
		return 0, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return count, nil
}

func RevokeDelete(ctx context.Context, client *mongo.Client, email string, jti string) (*mongo.DeleteResult, error) {
	database := client.Database(variable.AuthDatabase)

	revokeCollection := database.Collection(variable.RevokesCollection)

	deleted, err := revokeCollection.DeleteOne(ctx, bson.M{
		"email": email,
		"jti":   jti,
	})
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return deleted, nil
}
EOL

# create server/model/transaction.model.go
generate "./server/model/transaction.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/connection"
	"${project_name}/server/variable"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Transaction struct {
	ID          *primitive.ObjectID \'json:"_id,omitempty" bson:"_id,omitempty"\'
	Email       *string             \'json:"email,omitempty" bson:"email,omitempty"\'
	Code        *string             \'json:"code,omitempty" bson:"code,omitempty"\' // order_id
	GrossAmount *int64              \'json:"gross_amount,omitempty" bson:"gross_amount,omitempty"\'
	Note        *string             \'json:"note,omitempty" bson:"note,omitempty"\'

	// with payment gateway
	SnapURL       *string \'json:"snap_url,omitempty"    bson:"snap_url,omitempty"\'
	Status        *string \'json:"status,omitempty"      bson:"status,omitempty"\' // PENDING, PAID, CANCEL, REJECTED
	PaymentMethod *string \'json:"payment_method,omitempty"  bson:"payment_method,omitempty"\'

	CreatedAt *primitive.DateTime \'json:"created_at,omitempty" bson:"created_at,omitempty"\'
	PaymentAt *primitive.DateTime \'json:"payment_at,omitempty" bson:"payment_at,omitempty"\'
}

func TransactionMigrate(ctx context.Context, client *mongo.Client) {
	MongoDB := connection.MongoDB{}
	MongoDB.CreateIndex(ctx, client.Database(variable.TransactionDatabase), variable.TransactionsCollection, []connection.MongoDbIndex{
		{
			Name:   "code_unique",
			Unique: true,
			Keys:   bson.M{"code": 1},
		},
		{
			Name: "search_email",
			Keys: bson.M{"email": 1},
		},
		{
			Name: "search_code",
			Keys: bson.M{"code": 1},
		},
		{
			Name: "search_email_code",
			Keys: bson.M{"email": 1, "code": 1},
		},
		{
			Name: "search_email_status",
			Keys: bson.M{"email": 1, "status": 1},
		},
		{
			Name: "search_status",
			Keys: bson.M{"status": 1},
		},
	})
}

func TransactionCreate(ctx context.Context, client *mongo.Client, transaction Transaction) (result *mongo.InsertOneResult, err error) {
	database := client.Database(variable.TransactionDatabase)
	collection := database.Collection(variable.TransactionsCollection)

	now := primitive.NewDateTimeFromTime(time.Now())
	transaction.CreatedAt = &now
	result, err = collection.InsertOne(ctx, transaction)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return result, nil
}

func TransactionList(ctx context.Context, client *mongo.Client, filter bson.M, options *options.FindOptions) ([]Transaction, error) {
	database := client.Database(variable.TransactionDatabase)
	collection := database.Collection(variable.TransactionsCollection)

	proofs := make([]Transaction, 0)
	cursor, err := collection.Find(ctx, filter, options)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if err := cursor.All(ctx, &proofs); err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return proofs, nil
}

func TransactionUpdateStatus(ctx context.Context, client *mongo.Client, code string, status string, paymentMethod string) error {
	database := client.Database(variable.TransactionDatabase)
	collection := database.Collection(variable.TransactionsCollection)

	status = strings.ToLower(status)
	now := primitive.NewDateTimeFromTime(time.Now())
	result, err := collection.UpdateOne(
		ctx,
		bson.M{"code": code},
		bson.M{
			"$set": bson.M{
				"status":         status,
				"payment_method": paymentMethod,
				"updated_at":     now,
			},
		},
	)
	if err != nil || result.ModifiedCount == 0 {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to update proof of payment status")
	}

	return nil
}
EOL

# create server/model/user.model.go
generate "./server/model/user.model.go" << EOL
package model

import (
	"context"
	"${project_name}/server/connection"
	"${project_name}/server/variable"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type User struct {
	ID       *primitive.ObjectID \'bson:"_id,omitempty" json:"_id,omitempty"\'
	Email    *string             \'bson:"email,omitempty" json:"email,omitempty"\'         // SSO
	RoleCode *string             \'bson:"role_code,omitempty" json:"role_code,omitempty"\' // admin,
	Balance  *int64              \'bson:"balance,omitempty" json:"balance,omitempty"\'     // default: 0

	// Info
	Name    *string \'bson:"name,omitempty" json:"name,omitempty"\'
	Address *string \'bson:"address,omitempty" json:"address,omitempty"\'

	Whatsapp *string \'bson:"whatsapp,omitempty" json:"whatsapp,omitempty"\'

	// Settings
	IsDarkMode *bool \'bson:"is_dark_mode,omitempty" json:"is_dark_mode,omitempty"\' // default: false
	IsActive   *bool \'bson:"is_active,omitempty" json:"is_active,omitempty"\'       // default: true

	// timestamps (SLA)
	CreatedAt *primitive.DateTime \'json:"created_at,omitempty"  bson:"created_at,omitempty"\'
	UpdatedAt *primitive.DateTime \'json:"updated_at,omitempty"  bson:"updated_at,omitempty"\'

	UpdateHistory *[]User \'bson:"update_history,omitempty" json:"update_history,omitempty"\'
}

func UserMigrate(ctx context.Context, client *mongo.Client) {
	MongoDB := connection.MongoDB{}
	MongoDB.CreateIndex(ctx, client.Database(variable.UserDatabase), variable.UsersCollection, []connection.MongoDbIndex{
		{
			Name:   "email_unique",
			Unique: true,
			Keys:   bson.M{"email": 1},
		},
		{
			Name: "role_code_unique",
			Keys: bson.M{"role_code": 1},
		},
	})
}

func UserRegister(ctx context.Context, client *mongo.Client, user User) (*mongo.InsertOneResult, error) {
	database := client.Database(variable.UserDatabase)

	userCollection := database.Collection(variable.UsersCollection)

	now := primitive.NewDateTimeFromTime(time.Now())
	user.CreatedAt = &now
	inserted, err := userCollection.InsertOne(ctx, user)
	if err != nil {
		return inserted, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return inserted, nil
}

func UserGetByEmail(ctx context.Context, client *mongo.Client, email string) (*User, error) {
	database := client.Database(variable.UserDatabase)

	userCollection := database.Collection(variable.UsersCollection)

	var user *User
	err := userCollection.FindOne(ctx, bson.M{
		"email": email,
	}).Decode(&user)
	if err != nil && err != mongo.ErrNoDocuments {
		return user, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return user, nil
}

func UserUpdateByEmail(ctx context.Context, client *mongo.Client, email string, newData User) (*User, error) {
	database := client.Database(variable.UserDatabase)

	userCollection := database.Collection(variable.UsersCollection)

	// Get current user data
	var currentUser User
	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&currentUser)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusNotFound, "user not found")
	}

	// Create a copy of current user data for history
	historyData := currentUser
	historyData.UpdatedAt = nil
	historyData.UpdateHistory = nil

	// Initialize update history if nil
	if currentUser.UpdateHistory == nil {
		emptyHistory := make([]User, 0)
		currentUser.UpdateHistory = &emptyHistory
	}

	// Add current data to history
	*currentUser.UpdateHistory = append(*currentUser.UpdateHistory, historyData)

	// Set new data
	now := primitive.NewDateTimeFromTime(time.Now())
	newData.UpdatedAt = &now
	newData.UpdateHistory = currentUser.UpdateHistory

	// Update user
	updated := User{}
	err = userCollection.FindOneAndUpdate(ctx, bson.M{
		"email": email,
	}, bson.M{
		"$set": newData,
	}).Decode(&updated)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return &User{
		Name:    newData.Name,
		Address: newData.Address,
		//
		Whatsapp: newData.Whatsapp,
	}, nil
}

func UserUpdateBalance(ctx context.Context, client *mongo.Client, email string, amount int64) error {
	database := client.Database(variable.UserDatabase)
	collection := database.Collection(variable.UsersCollection)

	_, err := collection.UpdateOne(ctx, bson.M{
		"email": email,
	}, bson.M{
		"$inc": bson.M{
			"balance": amount,
		},
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return nil
}
EOL






# >> Server (Module)

# create server/module/auth.module.go
generate "./server/module/auth.module.go" << EOL
package module

import (
	"fmt"
	"${project_name}/server/auth"
	"${project_name}/server/connection"
	"${project_name}/server/middleware"
	"${project_name}/server/model"
	"${project_name}/server/util"
	"${project_name}/server/variable"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Auth struct{}

func (ref Auth) Route(api fiber.Router) {

	route := api.Group("/auth")
	v1 := route.Group("/v1")

	sso := AuthSsoHandler{}
	v1.Get("/sso/:provider", sso.Begin)
	v1.Get("/sso/:provider/callback", sso.Callback)

	auth := AuthHandler{}
	v1.Post("/register", auth.Register)
	v1.Post("/login", auth.Login)
	v1.Get("/token-validation", middleware.UseToken, auth.TokenValidation)
	v1.Delete("/logout", middleware.UseToken, auth.Logout)
	v1.Get("/login-history", middleware.UseToken, auth.LoginHistory)

}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------

type AuthSsoHandler struct{}

func (handler AuthSsoHandler) Begin(c *fiber.Ctx) error {
	Goth := auth.Goth{}
	url, err := Goth.GetAuthURL(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	return c.JSON(fiber.Map{
		"data": fiber.Map{
			"url": url,
		},
	})
}

func (handler AuthSsoHandler) Callback(c *fiber.Ctx) error {
	Goth := auth.Goth{}
	user, err := Goth.CompleteUserAuth(c)
	if err != nil {
		log.Println(err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	email := user.Email

	user_exist, err := model.UserGetByEmail(ctx, client, email)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	roleCode := variable.UserRole
	IsActive := true
	balance := int64(0)
	if user_exist != nil {
		roleCode = *user_exist.RoleCode
	} else {
		// insert new user
		if email == "jefriherditriyanto@gmail.com" {
			roleCode = variable.AdministratorRole
		}
		_, err := model.UserRegister(ctx, client, model.User{
			Email:    &user.Email,
			RoleCode: &roleCode,
			Name:     &user.Name,
			Address:  &user.Location,
			IsActive: &IsActive,
			Balance:  &balance,
			// Nickname:    user.NickName,
			// Description: user.Description,
			// UserID:      user.UserID,
			// AvatarURL:   user.AvatarURL,
		})
		if err != nil {
			return util.ErrorHandling(c, err)
		}
	}

	JWT := util.JWT{}
	token, jti, err := JWT.Generate(user.Email, user.Name, roleCode) // Short-lived token for access
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("generate token %s", err.Error()),
		})
	}

	expired_token := time.Now().Add(time.Hour * 24 * 7) // 7 hari
	expired_at := primitive.NewDateTimeFromTime(expired_token)

	// insert ke revokes
	now := primitive.NewDateTimeFromTime(time.Now())
	err = model.RevokeInsert(ctx, client, model.Revoke{
		Email:     &email,
		JwtID:     &jti,
		ExpiredAt: &now,
	})
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	device_id := c.Get("X-Device-ID")
	user_agent := c.Get("user-agent")

	// insert ke login_history
	ip := c.IP()
	err = model.LoginHistoryInsert(ctx, client, model.LoginHistory{
		Email:     &email,
		JwtID:     &jti,
		UserAgent: &user_agent,
		IpAddress: &ip,
		DeviceID:  &device_id,
		LoginAt:   &now,
		ExpiredAt: &expired_at,
	})
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	err = model.DeviceInsertIfNotExist(ctx, client, email, device_id, user_agent)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "success",
		"token":   token,
	})
}

// ---------------------------------------------------------------------------------------------

type AuthHandler struct{}

func (handler AuthHandler) Register(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "success",
	})
}

func (handler AuthHandler) Login(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "success",
	})
}

func (handler AuthHandler) TokenValidation(c *fiber.Ctx) error {
	user := c.Locals("user").(model.User)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"data": fiber.Map{
			"user": fiber.Map{
				"id":           user.ID,
				"email":        user.Email,
				"role_code":    user.RoleCode,
				"balance":      user.Balance,
				"name":         user.Name,
				"address":      user.Address,
				"whatsapp":     user.Whatsapp,
				"is_active":    user.IsActive,
				"is_dark_mode": user.IsDarkMode,
			},
		},
	})
}

func (handler AuthHandler) Logout(c *fiber.Ctx) error {
	email := c.Locals("email").(string)
	jti := c.Locals("jti").(string)

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	_, err = model.RevokeDelete(ctx, client, email, jti)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "success logout",
	})
}

func (handler AuthHandler) LoginHistory(c *fiber.Ctx) error {
	email := c.Locals("email").(string)

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	rows, err := model.LoginHistoryAll(ctx, client, email)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"rows": rows,
	})
}
EOL

# create server/module/callback.module.go
generate "./server/module/callback.module.go" << EOL
package module

import (
	"fmt"
	"${project_name}/server/connection"
	"${project_name}/server/dto"
	"${project_name}/server/model"

	"github.com/gofiber/fiber/v2"
)

type Callback struct{}

func (ref Callback) Route(api fiber.Router) {
	handler := CallbackHandler{}
	route := api.Group("/callback")

	route.Get("/", handler.HelloWorld)
	route.Post("/update", handler.Update) // from sawang keuangan

}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------

type CallbackHandler struct{}

func (handler CallbackHandler) HelloWorld(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Hello World",
	})
}

func (handler CallbackHandler) Update(c *fiber.Ctx) error {
	var body dto.CallbackUpdateBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request body",
		})
	}
	fmt.Printf("body: %+v\n", body)

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	model.TransactionUpdateStatus(ctx, client, body.TrxID, body.Status, body.PaymentMethod)

	if body.Status == "PAID" {
		fmt.Println("update balance")
		// nambah balance di user
		model.UserUpdateBalance(ctx, client, body.Customer.Email, int64(body.Amount))
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Update",
	})
}
EOL

# create server/module/content.module.go
generate "./server/module/content.module.go" << EOL
package module

import (
	"github.com/gofiber/fiber/v2"
)

type Content struct{}

func (ref Content) Route(api fiber.Router) {
	handler := ContentHandler{}
	route := api.Group("/content")
	management := route.Group("/management")

	route.Get("/", handler.Getter)

	management.Get("/", handler.HelloWorld)
	management.Post("/:id", handler.HelloWorld)
	management.Put("/:id", handler.HelloWorld)
	management.Patch("/:id", handler.HelloWorld)
	management.Delete("/:id", handler.HelloWorld)

}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------

type ContentHandler struct{}

func (handler ContentHandler) HelloWorld(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Hello World",
	})
}

func (handler ContentHandler) Getter(c *fiber.Ctx) error {
	// get all query
	queryParams := c.Queries()

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "OK",
		"query":   queryParams,
	})
}
EOL

# create server/module/example.module.go
generate "./server/module/example.module.go" << EOL
package module

import (
	"${project_name}/server/enigma"
	"${project_name}/server/util"

	"github.com/gofiber/fiber/v2"
)

type Example struct{}

func (ref Example) Route(api fiber.Router) {
	handler := ExampleHandler{}
	route := api.Group("/example")

	route.Get("/", handler.HelloWorld)
	route.Get("/trigger/:value", handler.Trigger)
	route.Get("/encode/:browser_id", handler.Encode)

}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------

type ExampleHandler struct{}

func (handler ExampleHandler) HelloWorld(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Hello World",
	})
}

func (handler ExampleHandler) Trigger(c *fiber.Ctx) error {
	// var err error

	subdomain, _ := c.Locals("subdomain").(string)
	browserID, _ := c.Locals("browser_id").(string)
	partaiID, _ := c.Locals("partai_id").(string)

	value := c.Params("value")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":    "OK",
		"value":      value,
		"subdomain":  subdomain,
		"browser_id": browserID,
		"partai_id":  partaiID,
	})
}

func (handler ExampleHandler) Encode(c *fiber.Ctx) error {
	var err error

	browser_id := c.Params("browser_id")

	Encryption := util.Encryption{}
	browser_id, err = Encryption.Encode(enigma.General("oke"), browser_id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":    "OK",
		"browser_id": browser_id,
	})
}
EOL

# create server/module/topup.module.go
generate "./server/module/topup.module.go" << EOL
package module

import (
	"fmt"
	"${project_name}/server/connection"
	"${project_name}/server/dto"
	"${project_name}/server/middleware"
	"${project_name}/server/model"
	"${project_name}/server/service"
	"${project_name}/server/util"
	"${project_name}/server/variable"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

type Topup struct{}

func (ref Topup) Route(api fiber.Router) {
	handler := TopupHandler{}
	route := api.Group("/topup")

	v1 := route.Group("/v1")
	v1.Get("/", handler.HelloWorld)
	v1.Post("/create", middleware.UseToken, middleware.RoleAccess([]string{variable.UserRole}), handler.Create)

}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------

type TopupHandler struct{}

func (handler TopupHandler) HelloWorld(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Hello World",
	})
}

func (handler TopupHandler) Create(c *fiber.Ctx) error {
	// Get user from token
	claims := c.Locals("claims").(jwt.MapClaims)
	email := claims["email"].(string)
	name := claims["name"].(string)

	var body dto.TopupCreateBody
	if err := util.BodyValidator(c, &body); err != nil {
		return err
	}

	// if topup under 55000 return error
	if body.Amount < 55000 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Topup amount must be at least Rp.55.000",
		})
	}

	trx, err := service.SawangKeuanganCreatePayment(service.SawangKeuanganPaymentRequest{
		CustomerName:  name,
		CustomerEmail: email,
		Items: []service.SawangKeuanganItem{
			{
				Name:     "Topup",
				Price:    body.Amount,
				Qty:      1,
				Category: "topup",
			},
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("create sawang keuangan %s", err.Error()),
		})
	}

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	note := "Topup"
	gross_amount := int64(body.Amount)
	status := "pending"
	model.TransactionCreate(ctx, client, model.Transaction{
		Email:       &email,
		Code:        &trx.TrxID,
		GrossAmount: &gross_amount,
		Note:        &note,
		SnapURL:     &trx.SnapURL,
		Status:      &status,
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "success",
		"data": fiber.Map{
			"snap_url": trx.SnapURL,
		},
	})
}
EOL

# create server/module/transaction.module.go
generate "./server/module/transaction.module.go" << EOL
package module

import (
	"fmt"
	"${project_name}/server/connection"
	"${project_name}/server/middleware"
	"${project_name}/server/model"
	"${project_name}/server/util"
	"${project_name}/server/variable"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
)

type Transaction struct{}

func (ref Transaction) Route(api fiber.Router) {
	handler := TransactionHandler{}
	route := api.Group("/transaction")
	v1 := route.Group("/v1")

	v1.Get("/", handler.HelloWorld)
	v1.Get("/list", middleware.UseToken, middleware.RoleAccess([]string{variable.UserRole}), handler.List)

}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------

type TransactionHandler struct{}

func (handler TransactionHandler) HelloWorld(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Hello World",
	})
}

func (handler TransactionHandler) List(c *fiber.Ctx) error {
	claims := c.Locals("claims").(jwt.MapClaims)
	email := claims["email"].(string)

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	rows, err := model.TransactionList(ctx, client, bson.M{"email": email}, nil)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "success",
		"data": fiber.Map{
			"rows": rows,
		},
	})
}
EOL

# create server/module/user.module.go
generate "./server/module/user.module.go" << EOL
package module

import (
	"fmt"
	"${project_name}/server/connection"
	"${project_name}/server/dto"
	"${project_name}/server/middleware"
	"${project_name}/server/model"
	"${project_name}/server/util"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

type User struct{}

func (ref User) Route(api fiber.Router) {
	handler := UserHandler{}
	route := api.Group("/user")

	route.Get("/", handler.HelloWorld)
	route.Put("/edit", middleware.UseToken, handler.Edit)

}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

type UserHandler struct{}

func (handler UserHandler) HelloWorld(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Hello World",
	})
}

func (handler UserHandler) Edit(c *fiber.Ctx) error {
	var body dto.UserEditBody
	if err := util.BodyValidator(c, &body); err != nil {
		return err
	}

	claims := c.Locals("claims").(jwt.MapClaims)
	email := claims["email"].(string)

	// Convert DTO to model
	userUpdate := model.User{
		Name:    &body.Name,
		Address: &body.Address,
		//
		Whatsapp: &body.Whatsapp,
	}

	MongoDB := connection.MongoDB{}
	client, ctx, err := MongoDB.Connect()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("connect mongodb %s", err.Error()),
		})
	}
	defer client.Disconnect(ctx)

	// Update user
	result, err := model.UserUpdateByEmail(ctx, client, email, userUpdate)
	if err != nil {
		return util.ErrorHandling(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Profile updated successfully",
		"data":    result,
	})
}
EOL








# >> Server (Service)

# create server/service/sawang.service.go
generate "./server/service/sawang.service.go" << EOL
package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"${project_name}/server/env"
	"io/ioutil"
	"net/http"
)

// Struct untuk item
type SawangKeuanganItem struct {
	Name     string 'json:"name"'
	Price    int    'json:"price"'
	Qty      int    'json:"qty"'
	Category string 'json:"category"'
}

// Struct untuk payload request
type SawangKeuanganPaymentRequest struct {
	CustomerName  string               'json:"customer_name"'
	CustomerEmail string               'json:"customer_email"'
	Items         []SawangKeuanganItem 'json:"items"'
}

type SawangKeuanganDataResponse struct {
	SnapURL string 'json:"snap_url"'
	TrxID   string 'json:"trx_id"'
}
type SawangKeuanganResponse struct {
	Data    SawangKeuanganDataResponse 'json:"data"'
	Message string                     'json:"message"'
}

func SawangKeuanganCreatePayment(payload SawangKeuanganPaymentRequest) (*SawangKeuanganDataResponse, error) {
	url := "https://keuangan.sawang.tech"
	url = fmt.Sprintf("%s/api/integration/v1/create-payment", url)

	// Encode payload ke JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Buat request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	x_environment := env.GetSawangKeuanganXEnvironment()
	x_api_key := env.GetSawangKeuanganXApiKey()

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Environment", x_environment)
	req.Header.Set("X-Api-Key", x_api_key)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Baca response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response SawangKeuanganResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response.Data, nil
}
EOL







# >> Server (Util)

# create server/util/encryption.util.go
generate "./server/util/encryption.util.go" << EOL
package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

type Encryption struct{}

type EncryptionMethod string

const (
	AES       EncryptionMethod = "AES"
	TripleDES EncryptionMethod = "TripleDES"
	DES       EncryptionMethod = "DES"
	RC4       EncryptionMethod = "RC4"
	Base64    EncryptionMethod = "base64"
)

type EnigmaSchema struct {
	Method EncryptionMethod
	Key    func() string
}

// Helper function to hash the key using SHA256
func hashKey(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

// Helper function to reverse strings
func ReverseStrings(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// AES Encryption and Decryption
func encryptAES(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAES(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := data[:aes.BlockSize]
	plaintext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, plaintext)

	return string(plaintext), nil
}

// DES Encryption and Decryption
func encryptDES(key []byte, plaintext string) (string, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptDES(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := data[:des.BlockSize]
	plaintext := data[des.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, plaintext)

	return string(plaintext), nil
}

// TripleDES Encryption and Decryption
func encryptTripleDES(key []byte, plaintext string) (string, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptTripleDES(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	iv := data[:des.BlockSize]
	plaintext := data[des.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, plaintext)

	return string(plaintext), nil
}

// RC4 Encryption and Decryption
func encryptRC4(key []byte, plaintext string) (string, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptRC4(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(data))
	cipher.XORKeyStream(plaintext, data)

	return string(plaintext), nil
}

// Apply encryption or decryption method
func applyMethod(text string, layer EnigmaSchema, isEncrypt bool) (string, error) {
	if layer.Method == Base64 {
		if isEncrypt {
			return base64.StdEncoding.EncodeToString([]byte(text)), nil
		}
		data, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return "", err
		}
		return string(data), nil
	} else if layer.Key != nil {
		key := hashKey(layer.Key())
		switch layer.Method {
		case AES:
			if isEncrypt {
				return encryptAES(key, text)
			} else {
				return decryptAES(key, text)
			}
		case DES:
			if isEncrypt {
				return encryptDES(key, text)
			} else {
				return decryptDES(key, text)
			}
		case TripleDES:
			if isEncrypt {
				return encryptTripleDES(key, text)
			} else {
				return decryptTripleDES(key, text)
			}
		case RC4:
			if isEncrypt {
				return encryptRC4(key, text)
			} else {
				return decryptRC4(key, text)
			}
		}
	}
	return "", errors.New(fmt.Sprintf("Key function missing for method: %s", layer.Method))
}

// Encode applies encryption layers to the input text
func (ref Encryption) Encode(enigmaSchema []EnigmaSchema, text string) (string, error) {
	var err error
	cipherText := text
	for _, layer := range enigmaSchema {
		cipherText, err = applyMethod(cipherText, layer, true)
		if err != nil {
			return "", err
		}
	}
	return cipherText, nil
}

// Decode applies decryption layers to the input cipher text
func (ref Encryption) Decode(enigmaSchema []EnigmaSchema, encrypted string) (string, error) {
	var err error
	plainText := encrypted
	for i := len(enigmaSchema) - 1; i >= 0; i-- {
		plainText, err = applyMethod(plainText, enigmaSchema[i], false)
		if err != nil {
			return "", err
		}
	}
	return plainText, nil
}
EOL

# create server/util/env.util.go
generate "./server/util/env.util.go" << EOL
package util

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"${project_name}/server/env"

	"github.com/joho/godotenv"
)

type Env struct{}

func (ref Env) Load() {
	pwd := env.GetPwd()
	envFilePath := filepath.Join(pwd, ".env")
	err := godotenv.Load(envFilePath)
	if err != nil {
		fmt.Println("file .env not found")
	}
}

func (ref Env) SetTimezone() error {
	timezone := "Asia/Jakarta"
	os.Setenv("TZ", timezone)
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		fmt.Println("Error loading location:", err)
		return err
	}
	time.Local = loc
	return nil
}
EOL

# create server/util/error.util.go
generate "./server/util/error.util.go" << EOL
package util

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

func ErrorHandling(c *fiber.Ctx, err error) error {
	if fiberErr, ok := err.(*fiber.Error); ok {
		return c.Status(fiberErr.Code).JSON(fiber.Map{
			"message": fiberErr.Message,
		})
	}
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"message": fmt.Sprintf("error getting user by email: %s", err.Error()),
	})
}
EOL

# create server/util/fiber.util.go
generate "./server/util/fiber.util.go" << EOL
package util

import (
	"fmt"
	"mime/multipart"
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func UploadFile(c *fiber.Ctx, file *multipart.FileHeader, uploadPath string) (string, error) {
	// Get file extension
	extension := filepath.Ext(file.Filename)
	// Generate unique filename
	filename := fmt.Sprintf("%s%s", uuid.New().String(), extension)
	folderPath := fmt.Sprintf("uploads/%s", uploadPath)
	// Create directory if it doesn't exist
	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	// Save file to storage
	err := c.SaveFile(file, fmt.Sprintf("%s/%s", folderPath, filename))
	if err != nil {
		return "", err
	}

	return filename, nil
}

func GetFile(uploadPath string, filename string) (string, error) {
	// Construct full file path
	filePath := fmt.Sprintf("uploads/%s/%s", uploadPath, filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found: %s", filename)
	}

	return filePath, nil
}
EOL

# create server/util/format.util.go
generate "./server/util/format.util.go" << EOL
package util

import "strconv"

func ParseFloat64(value string) (float64, error) {
	return strconv.ParseFloat(value, 64)
}
EOL

# create server/util/generate.model.go
generate "./server/util/generate.model.go" << EOL
package util

import (
	"math/rand"

	"github.com/google/uuid"
)

type Generate struct{}

func (ref Generate) OTP(length int) string {
	const otpChars = "1234567890"
	otp := make([]byte, length)
	for i := range otp {
		otp[i] = otpChars[rand.Intn(len(otpChars))]
	}
	return string(otp)
}

func (ref Generate) UUIDv4() string {
	return uuid.New().String()
}
EOL

# create server/util/jwt.util.go
generate "./server/util/jwt.util.go" << EOL
package util

import (
	"${project_name}/server/env"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

type JWT struct{}

type JwtClaims struct {
	Email     string 'json:"email"'
	Name      string 'json:"name"'
	FirstName string 'json:"first_name"'
	LastName  string 'json:"last_name"'
	RoleCode  string 'json:"role_code"'
	Iat       int64  'json:"iat"'
	Jti       string 'json:"jti"'
}

func (ref JWT) Generate(email string, name string, role_code string) (string, string, error) {
	secretKey := env.GetSecretKey()
	Generate := Generate{}
	jti := Generate.UUIDv4()
	claims := jwt.MapClaims{
		"email":     email,
		"name":      name,
		"role_code": role_code,
		"iat":       time.Now().Unix(),
		"jti":       jti, // Assign JTI to the JWT claims
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token_str, err := token.SignedString([]byte(secretKey))
	return token_str, jti, err
}

func (ref JWT) Validate(tokenString string) (jwt.MapClaims, error) {
	secretKey := env.GetSecretKey()
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "unexpected signing method")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fiber.NewError(fiber.StatusUnauthorized, "invalid token")
}
EOL

# create server/util/mongodb.util.go
generate "./server/util/mongodb.util.go" << EOL
package util

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func PaginateMongo(model interface{}, collection *mongo.Collection, c *fiber.Ctx, filter bson.M, page, limit int, orderBy, order string) error {
	// Tentukan skip dan limit untuk pagination
	skip := (page - 1) * limit

	// Tentukan opsi pencarian
	opts := options.Find()
	opts.SetSkip(int64(skip))
	opts.SetLimit(int64(limit))
	sortOrder := 1
	if order == "desc" {
		sortOrder = -1
	}
	opts.SetSort(bson.D{{Key: orderBy, Value: sortOrder}})

	// Lakukan pencarian
	cursor, err := collection.Find(c.Context(), filter, opts)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("internal server error %s", err.Error()),
		})
	}
	defer cursor.Close(c.Context())

	// Dekode hasil pencarian ke dalam slice dari map
	var results []bson.M
	if err := cursor.All(c.Context(), &results); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("error decoding results %s", err.Error()),
		})
	}

	// Hapus field password dari setiap object
	for _, result := range results {
		delete(result, "password")
	}

	// Inisialisasi results sebagai slice kosong jika tidak ada data
	if len(results) == 0 {
		results = []bson.M{}
	}

	// Hitung total dokumen
	total, err := collection.CountDocuments(c.Context(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": fmt.Sprintf("error counting documents %s", err.Error()),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"data":  results,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}
EOL

# create server/util/pagination.util.go
generate "./server/util/pagination.util.go" << EOL
package util

import (
	"context"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ParsePaginationParams parses pagination and sorting query parameters
func PaginationParseParams(c *fiber.Ctx) (int, int, string, int) {
	// Parse query parameters
	page, err := strconv.Atoi(c.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.Query("limit", "10"))
	if err != nil || limit < 1 {
		limit = 10
	}
	sortBy := c.Query("sortby", "_id")

	// Parse sort order, default is descending (-1)
	sortOrderParam := c.Query("order", "desc")
	sortOrder := 1 // Default to Ascending
	if sortOrderParam == "desc" {
		sortOrder = -1 // Descending
	}

	return page, limit, sortBy, sortOrder
}

// GetPaginatedResults fetches documents with pagination from a MongoDB collection
func PaginateGetResults[T any](
	ctx context.Context,
	collection *mongo.Collection,
	page int,
	limit int,
	sortBy string,
	sortOrder int,
	filter bson.M,
) ([]T, error) {
	// Create filter and sort options
	findOptions := options.Find()
	findOptions.SetSkip(int64((page - 1) * limit))
	findOptions.SetLimit(int64(limit))
	findOptions.SetSort(bson.D{{sortBy, sortOrder}})

	// Retrieve documents with pagination
	results := make([]T, 0)
	cursor, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	// Decode the cursor into the results slice
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// GetTotalPages calculates the total pages for pagination
func PaginationGetTotalPages(ctx context.Context, collection *mongo.Collection, filter bson.M, limit int) (int, error) {
	// Count total documents for pagination
	totalDocuments, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}
	lastPage := int(totalDocuments) / limit
	if int(totalDocuments)%limit != 0 {
		lastPage++
	}
	return lastPage, nil
}
EOL

# create server/util/rest.util.go
generate "./server/util/rest.util.go" << EOL
package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type RestOptions struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    interface{} // Bisa diisi dengan struct, map, atau nil jika tidak ada body
}

type RestResponseError struct {
	StatusCode int    \'json:"status_code"\'
	Message    string \'json:"message"\'
	Response   string \'json:"response"\'
}

type RestErrorMessage struct {
	Message string \'json:"message"\'
}

func ParseErrorResponse(response string) (*RestErrorMessage, error) {
	// Periksa apakah response tidak kosong
	if response == "" {
		return nil, fmt.Errorf("empty response")
	}

	// Buat struct untuk memegang message dari JSON
	var errorMsg RestErrorMessage

	// Unmarshal response JSON ke dalam struct RestErrorMessage
	err := json.Unmarshal([]byte(response), &errorMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &errorMsg, nil
}

func RestHit[T any](options RestOptions) (*T, RestResponseError) {
	// Marshal body ke JSON jika ada body
	var reqBody []byte
	var err error
	if options.Body != nil {
		reqBody, err = json.Marshal(options.Body)
		if err != nil {
			return nil, RestResponseError{
				StatusCode: 500,
				Message:    fmt.Sprintf("failed to marshal body: %v", err),
			}
		}
	}

	// Buat request HTTP baru
	req, err := http.NewRequest(options.Method, options.URL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, RestResponseError{
			StatusCode: 500,
			Message:    fmt.Sprintf("failed to create request: %v", err),
		}
	}

	// Tambahkan headers
	for key, value := range options.Headers {
		req.Header.Set(key, value)
	}

	// Set Content-Type untuk POST atau PUT
	if options.Method == http.MethodPost || options.Method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}

	// Tambahkan timeout untuk client
	client := &http.Client{
		Timeout: 10 * time.Second, // Tambahkan timeout agar tidak menggantung
	}

	// Kirim request
	resp, err := client.Do(req)
	if err != nil {
		return nil, RestResponseError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("failed to send request: %v", err),
		}
	}
	defer resp.Body.Close()

	// Pastikan response status code adalah 2xx
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Baca response body untuk memberikan error yang lebih informatif
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return nil, RestResponseError{
			StatusCode: resp.StatusCode,
			Response:   bodyString,
		}
	}

	// Decode response body ke dalam struct T
	var result T
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, RestResponseError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("failed to unmarshal response: %v", err),
		}
	}

	return &result, RestResponseError{}
}
EOL

# create server/util/validate.util.go
generate "./server/util/validate.util.go" << EOL
package util

import (
	"fmt"
	"regexp"
	"strconv"
)

func NumberOnly(value interface{}) (int, error) {
	var number int
	switch v := value.(type) {
	case int:
		number = v
	case int32:
		number = int(v)
	case float64:
		number = int(v)
	case string:
		p, err := strconv.Atoi(v)
		if err != nil {
			return 0, err
		}
		number = p
	default:
		return 0, fmt.Errorf("value harus berupa angka")
	}

	return number, nil
}

func IsPhoneNumber(phoneNumber string) bool {
	// Pola regex untuk validasi nomor telepon internasional
	regex := \'\+(9[976]\d|8[987530]\d|6[987]\d|5[90]\d|42\d|3[875]\d|2[98654321]\d|9[8543210]|8[6421]|6[6543210]|5[87654321]|4[987654310]|3[9643210]|2[70]|7|1)\d{1,14}$\'

	// Membuat objek regex
	re := regexp.MustCompile(regex)

	// Mengecek apakah nomor telepon sesuai dengan pola regex
	return re.MatchString(phoneNumber)
}

func IsEmail(email string) bool {
	// Membuat objek regex untuk validasi email
	re := regexp.MustCompile(\'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$\')

	// Mengecek apakah email sesuai dengan pola regex
	return re.MatchString(email)
}

func IsPassword(password string) bool {
	// Membuat objek regex untuk validasi password
	re := regexp.MustCompile(\'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$\')

	// Mengecek apakah password sesuai dengan pola regex
	return re.MatchString(password)
}

func IsImageFile(contentType string) bool {
	// List of common image MIME types
	imageTypes := []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/bmp",
		"image/webp",
		"image/avif",
		"image/ico",
	}

	// Check if the content type is in the list of image types
	for _, imageType := range imageTypes {
		if contentType == imageType {
			return true
		}
	}

	return false
}

func IsVideoFile(contentType string) bool {
	// List of common video MIME types
	videoTypes := []string{
		"video/mp4",
		"video/mpeg",
		"video/quicktime",
		"video/x-msvideo",
		"video/x-matroska",
		"video/3gpp",
		"video/3gpp2",
		"video/webm",
		"video/ogg",
		"video/avi",
		"video/3gpp",
		"video/3gpp2",
		"video/webm",
		"video/ogg",
		"video/avi",
	}

	// Check if the content type is in the list of video types
	for _, videoType := range videoTypes {
		if contentType == videoType {
			return true
		}
	}

	return false
}

func IsAudioFile(contentType string) bool {
	// List of common audio MIME types
	audioTypes := []string{
		"audio/mpeg",
		"audio/mp3",
		"audio/wav",
		"audio/ogg",
		"audio/3gpp",
		"audio/3gpp2",
		"audio/webm",
		"audio/ogg",
		"audio/3gpp",
		"audio/3gpp2",
		"audio/webm",
		"audio/ogg",
		"audio/3gpp",
		"audio/3gpp2",
	}

	// Check if the content type is in the list of audio types
	for _, audioType := range audioTypes {
		if contentType == audioType {
			return true
		}
	}

	return false
}
EOL

# create server/util/validator.util.go
generate "./server/util/validator.util.go" << EOL
package util

import (
	"sync"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type UseValidator struct{}

var (
	Validator *validator.Validate
	once      sync.Once
)

func BodyValidator(c *fiber.Ctx, body interface{}) error {
	initValidator()

	if err := c.BodyParser(body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "invalid request body",
		})
	}

	if err := Validator.Struct(body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}

	return nil
}

func initValidator() {
	once.Do(func() {
		Validator = validator.New()
		Validator.RegisterValidation("array-required", validateArrayRequired)
	})
}

func validateArrayRequired(fl validator.FieldLevel) bool {
	return len(fl.Field().Interface().([]any)) > 0
}
EOL








# >> Server (Variable)

# create server/variable/collection.variable.go
generate "./server/variable/collection.variable.go" << EOL
package variable

var (
	SettingsCollection string = "settings"
	ContentsCollection string = "contents"

	// User & Auth ...
	UsersCollection          string = "users"
	DevicesCollection        string = "devices"
	RevokesCollection        string = "revokes"
	LoginHistoriesCollection string = "login_histories"
	RolesCollection          string = "roles"

	// Transaction ...
	TransactionsCollection        string = "transactions"
	TransactionProductsCollection string = "transaction_products"

	// Notification
	NotificationsCollection string = "notifications"

	// Dashboard
	DashboardsCollection string = "dashboards"
)
EOL

# create server/variable/database.variable.go
generate "./server/variable/database.variable.go" << EOL
package variable

const (
	NotificationDatabase string = "${project_name}_notification"
	ContentDatabase      string = "${project_name}_content"
	AuthDatabase         string = "${project_name}_auth"
	UserDatabase         string = "${project_name}_user"
	TransactionDatabase  string = "${project_name}_transaction"
	ContestDatabase      string = "${project_name}_contest"
	WarehouseDatabase    string = "${project_name}_warehouse"
)
EOL

# create server/variable/jwt.variable.go
generate "./server/variable/jwt.variable.go" << EOL
package variable

var KeyExpiredLoginJwt = "expired_login"
var KeyMaxLoginJwt = "max_login"
EOL

# create server/variable/role.variable.go
generate "./server/variable/role.variable.go" << EOL
package variable

const (
	AdministratorRole string = "administrator"
	UserRole          string = "user"
)
EOL

# create server/variable/status.variable.go
generate "./server/variable/status.variable.go" << EOL
package variable

const (
	PaymentPendingStatus  string = "pending"
	PaymentPaidStatus     string = "paid"
	PaymentRejectedStatus string = "rejected"
)
EOL





# >> Server

# create server/run.go
generate "./server/run.go" << EOL
package server

import (
	"embed"

	"${project_name}/server/http"
)

func Run(embeddedFiles embed.FS) {
	go func() {
		http.Server(embeddedFiles)
	}()
}
EOL

### ========================================================================== ###
###                                  Setup                                     ###
### ========================================================================== ###

echo "Setup..."

go mod tidy

# check jika tidak ada folder dist, maka buatkan dan berika index.html
if [ ! -d "dist" ]; then
    generate "./dist/index.html" << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hello World</title>
</head>
<body>
    <h1>Hello World</h1>
</body>
</html>
EOL
fi

# test compile
go build -o ${project_name}.exe main.go

### ========================================================================== ###

echo "Done!"
