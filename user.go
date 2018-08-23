package osin

import (
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// User information
type User interface {
	// User id
	GetId() int

	// User name
	GetName() string

	// User last name
	GetLastName() string

	// User email
	GetEmail() string

	// User password
	GetPassword() string

	// User update password
	SetPassword(pwd string)
}

func PasswordHashAndSalt(pwd []byte) string {

	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func ComparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

// DefaultUser stores all data in struct variables
type DefaultUser struct {
	Id       int
	Name     string
	LastName string
	Email    string
	Password string
}

func (d *DefaultUser) GetId() int {
	return d.Id
}

func (d *DefaultUser) GetName() string {
	return d.Name
}

func (d *DefaultUser) GetLastName() string {
	return d.LastName
}

func (d *DefaultUser) GetEmail() string {
	return d.Email
}

func (d *DefaultUser) GetPassword() string {
	return d.Password
}

func (d *DefaultUser) SetPassword(pwd string) {
	d.Password = PasswordHashAndSalt([]byte(pwd))
}

func (d *DefaultUser) CopyFrom(user User) {
	d.Id = user.GetId()
	d.Name = user.GetName()
	d.LastName = user.GetLastName()
	d.Email = user.GetEmail()
	d.Password = user.GetPassword()
}

func (s *Server) GetRequestUser(w *Response, r *http.Request) User {
	if infoRequest := s.HandleInfoRequest(w, r); infoRequest != nil {
		return infoRequest.AccessData.User
	}

	return nil
}
