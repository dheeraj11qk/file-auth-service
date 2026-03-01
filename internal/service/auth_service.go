package service

import (
	"auth-service/internal/models"
	"auth-service/internal/repository"
	"auth-service/pkg/jwt"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	repo       *repository.UserRepository
	jwtManager *jwt.Manager
}

func NewAuthService(repo *repository.UserRepository, jwtManager *jwt.Manager) *AuthService {
	return &AuthService{
		repo:       repo,
		jwtManager: jwtManager,
	}
}

func (s *AuthService) Register(email, password string) (string, error) {

	hashed, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", err
	}

	user := models.User{
		Email:    email,
		Password: string(hashed),
	}

	err = s.repo.Create(&user)
	if err != nil {
		return "", err
	}

	return s.jwtManager.Generate(user.ID)
}

func (s *AuthService) Login(email, password string) (string, error) {

	user, err := s.repo.FindByEmail(email)
	if err != nil {
		return "", err
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(password),
	)
	if err != nil {
		return "", err
	}

	return s.jwtManager.Generate(user.ID)
}
