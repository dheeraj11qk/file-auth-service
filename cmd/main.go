package main

import (
	"context"
	"os"
	"strconv"
	"time"

	"auth-service/internal/db"
	"auth-service/internal/handler"
	"auth-service/internal/models"
	"auth-service/internal/observability"
	"auth-service/internal/repository"
	"auth-service/internal/service"
	"auth-service/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func main() {

	// 1️⃣ Init Tracer FIRST
	shutdown := observability.InitTracer("auth-service")
	defer shutdown(context.Background())

	// Init DB
	db.InitDB()

	// Auto migrate
	db.DB.AutoMigrate(&models.User{})

	// Setup layers
	repo := repository.NewUserRepository(db.DB)

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		panic("JWT_SECRET is not set")
	}

	expireStr := os.Getenv("JWT_EXPIRE_HOURS")
	if expireStr == "" {
		panic("JWT_EXPIRE_HOURS is not set")
	}

	expireHours, err := strconv.Atoi(expireStr)
	if err != nil {
		panic("Invalid JWT_EXPIRE_HOURS value")
	}

	jwtManager := jwt.New(
		secret,
		time.Duration(expireHours)*time.Hour,
	)

	authService := service.NewAuthService(repo, jwtManager)
	authHandler := handler.NewAuthHandler(authService)

	// Gin
	r := gin.Default()

	// 4️⃣ Add OTEL middleware
	r.Use(otelgin.Middleware("auth-service"))
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	r.POST("/register", authHandler.Register)
	r.POST("/login", authHandler.Login)
	r.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"status":  "ok",
			"service": "auth-service",
		})
	})

	r.Run(":8080")
}
