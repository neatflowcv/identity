package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/config"
	"github.com/neatflowcv/identity/internal/pkg/hasher/argon"
	"github.com/neatflowcv/identity/internal/pkg/repository/orm"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
)

const (
	apiVersion        = "1.0.0"
	readHeaderTimeout = 5 * time.Second
)

func main() {
	appConfig, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	toker := jwt.NewToker(appConfig.JWTPublicKey, appConfig.JWTPrivateKey)

	repo, err := orm.NewRepository(appConfig.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to initialize repository:", err)
	}

	hasher := argon.NewDefaultArgon2id()

	service := flow.NewService(toker, repo, hasher)
	router := NewRouter(service)

	log.Printf("Starting server on :%d", appConfig.Port)
	log.Printf("OpenAPI JSON available at http://localhost:%d/identity/v1/openapi.json", appConfig.Port)
	log.Printf("OpenAPI YAML available at http://localhost:%d/identity/v1/openapi.yaml", appConfig.Port)
	log.Printf("API docs available at http://localhost:%d/identity/v1/docs", appConfig.Port)

	server := &http.Server{ //nolint:exhaustruct
		Addr:              ":" + strconv.Itoa(appConfig.Port),
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func NewRouter(service *flow.Service) *http.ServeMux {
	router := http.NewServeMux()
	config := huma.DefaultConfig("Identity API", apiVersion)
	config.OpenAPIPath = "/identity/v1/openapi"
	config.DocsPath = "/identity/v1/docs"
	config.SchemasPath = "/identity/v1/schemas"
	config.Info.Description = "This is an identity management API server."

	api := humago.New(router, config)
	NewHandler(service).Register(api)

	return router
}
