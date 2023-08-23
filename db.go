package main

import (
	"errors"
	"sync"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

type Id uint64

type User struct {
	Groups       []string `json:"groups"`
	Id           Id       `json:"id"`
	PasswordHash []byte   `json:"passwordHash"`
	Username     string   `json:"name"`
}

var inc Id = 0
var fakeDb = []User{}

var dbMutex = sync.Mutex{}

func Lookup(username string) *User {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	for _, u := range fakeDb {
		if u.Username == username {
			return &u
		}
	}
	return nil
}

func LookupId(id Id) *User {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	for _, u := range fakeDb {
		if u.Id == id {
			return &u
		}
	}
	return nil
}

func Insert(u *User) Id {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	u.Id = inc
	fakeDb = append(fakeDb, *u)
	inc++
	return u.Id
}

func okUsername(username string) bool {
	for _, c := range username {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' {
			continue
		}
		return false
	}
	return true
}

func Register(username, password string, groups []string) (Id, error) {

	if !okUsername(username) {
		return 0, errors.New("Invalid username")
	}

	if Lookup(username) != nil {
		return 0, errors.New("Username already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}

	user := &User{
		Id: 0,
		Username: username,
		PasswordHash: hash,
		Groups: groups,
	}

	id := Insert(user)
	return id, nil
}

func Login(username, password string) (*User, error) {
	u := Lookup(username)

	err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password))
	if err != nil {
		return nil, err
	}

	return u, nil
}
