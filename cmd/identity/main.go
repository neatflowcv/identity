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
	"github.com/neatflowcv/identity/internal/pkg/repository/orm"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
)

const (
	defaultPort       = 8080
	apiVersion        = "1.0.0"
	readHeaderTimeout = 5 * time.Second
)

func main() {
	port := defaultPort
	portValue := os.Getenv("PORT")

	if portValue != "" {
		parsedPort, err := strconv.Atoi(portValue)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			log.Fatal("Invalid PORT: must be an integer between 1 and 65535")
		}

		port = parsedPort
	}

	toker := jwt.NewToker([]byte("public-key"), []byte("private-key"))

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=postgres dbname=identity port=5432 sslmode=disable TimeZone=Asia/Seoul"
	}

	repo, err := orm.NewRepository(dsn)
	if err != nil {
		log.Fatal("Failed to initialize repository:", err)
	}

	service := flow.NewService(toker, repo)
	router := NewRouter(service)

	log.Printf("Starting server on :%d", port)
	log.Printf("OpenAPI JSON available at http://localhost:%d/identity/v1/openapi.json", port)
	log.Printf("OpenAPI YAML available at http://localhost:%d/identity/v1/openapi.yaml", port)
	log.Printf("API docs available at http://localhost:%d/identity/v1/docs", port)

	server := &http.Server{ //nolint:exhaustruct
		Addr:              ":" + strconv.Itoa(port),
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
