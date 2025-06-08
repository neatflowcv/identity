package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/neatflowcv/identity/docs"
	"github.com/neatflowcv/identity/internal/app/flow"
	"github.com/neatflowcv/identity/internal/pkg/repository/fake"
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
	toker := jwt.NewToker([]byte("secret"))
	repo := fake.NewRepository()
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

	log.Println("Starting server on :8080")
	log.Println("Swagger UI available at http://localhost:8080/identity/v1/docs")

	err := route.Run(":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
