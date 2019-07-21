package service

import "github.com/lehoangthienan/LibraryApi/service/user"

// Service define list of all services in projects
type Service struct {
	UserService user.Service
}
