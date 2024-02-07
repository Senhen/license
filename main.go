package main

import (
	"license/server"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func startServer() error {
	r := gin.Default()

	r.POST("/license/sign", server.LicenseSign)

	//gin设置超时时间
	r.Use(func(c *gin.Context) {
		c.Set("deadline", time.Now().Add(5*time.Second))
		c.Next()
	})

	var ServerPort = "9999"
	server := &http.Server{
		Addr:         ":" + ServerPort,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
		return err
	}
	return nil
}

func main() {
	err := startServer()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
		return
	}
}
