package main

import (
	"context"
	"log"

	"github.com/chapsuk/grace"

	"test-auth/internal/app"
)

// @title           Test task Back-Dev Auth API
// @version         1.0
// @description     API server for Auth API

// @host      192.168.77.110:8080
// @BasePath  /api

func main() {
	ctx := grace.ShutdownContext(context.Background())

	application, err := app.New(ctx)
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
	defer application.Shutdown()

	if err = application.Run(ctx); err != nil {
		log.Printf("application stopped with error: %v", err)
	}
}
