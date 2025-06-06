package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	route := gin.Default()
	handler := NewHandler()
	v1 := route.Group("/identity/v1")
	{
		v1.POST("/users", handler.CreateUser)
	}

	log.Println("Starting server on :8080")

	err := route.Run(":8080")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
