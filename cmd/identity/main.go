package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/neatflowcv/identity/docs"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/repository/orm"
	"github.com/neatflowcv/identity/internal/pkg/toker/jwt"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Identity API
// @version 1.0
// @description This is an identity management API server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Proprietary
// @license.url All Rights Reserved

// @host localhost:8080
// @BasePath /
func main() {
	route := gin.Default()
	toker := jwt.NewToker([]byte("public-key"), []byte("private-key"))

	// 환경변수에서 DSN을 가져오거나 기본값 사용
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=postgres dbname=identity port=5432 sslmode=disable TimeZone=Asia/Seoul"
	}

	// 환경변수에서 PORT를 가져오거나 기본값 사용
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	repo, err := orm.NewRepository(dsn)
	if err != nil {
		log.Fatal("Failed to initialize repository:", err)
	}

	service := flow.NewService(toker, repo)
	handler := NewHandler(service)

	base := route.Group("/identity/v1")
	{
		base.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		base.GET("/docs", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/identity/v1/swagger/index.html")
		})

		base.POST("/users", handler.CreateUser)
		base.POST("/tokens", handler.CreateToken)
		base.POST("/refresh", handler.RefreshToken)
	}

	log.Printf("Starting server on :%s", port)
	log.Printf("Swagger UI available at http://localhost:%s/identity/v1/docs", port)

	err = route.Run(":" + port)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
