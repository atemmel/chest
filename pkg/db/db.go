package db

import (
	"context"
	"errors"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
)

const (
	AdminGroup = "admin"
	UserGroup = "user"
	AnyGroup = ""
)

type User struct {
	Groups       []string              `json:"groups"`
	Id           primitive.ObjectID    `bson:"_id" json:"id,omitempty"`
	PasswordHash []byte                `json:"passwordHash"`
	Username     string                `json:"name"`
}

type createUser struct {
	Groups       []string `json:"groups"`
	PasswordHash []byte   `json:"passwordHash"`
	Username     string   `json:"name"`
}

func (u *User) PartOf(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true;
		}
	}
	return false;
}

var client *mongo.Client = nil

func collection() *mongo.Collection {
	return client.Database("chest").Collection("users")
}

func timeout(seconds time.Duration) (context.Context, func()) {
	return context.WithTimeout(context.Background(), seconds*time.Second)
}

func Connect() error {
	var err error
	client, err = mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return err
	}
	ctx, cancel := timeout(5)
	defer cancel()
	err = client.Ping(ctx, readpref.Primary())
	return err
}

func Disconnect() error {
	ctx, cancel := timeout(5)
	defer cancel()
	return client.Disconnect(ctx)
}

func Lookup(username string) *User {
	user := &User{}
	ctx, cancel := timeout(5)
	defer cancel()
	err := collection().FindOne(ctx, bson.D{{Key: "username", Value: username}}).Decode(user)
	if err != nil {
		return nil
	}
	return user
}

func LookupId(id primitive.ObjectID) *User {
	j := bson.D{{Key: "_id", Value: id}}
	u := &User{}
	ctx, cancel := timeout(5)
	defer cancel()
	err := collection().FindOne(ctx, j).Decode(u)
	if err != nil {
		return nil
	}
	return u
}

func LookupHexId(id string) *User {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil
	}
	return LookupId(oid)
}

func Insert(u *createUser) string {
	c := collection()
	ctx, cancel := timeout(5)
	defer cancel()
	result, err := c.InsertOne(ctx, u)
	if err != nil {
		panic(err)
	}
	id := result.InsertedID.(primitive.ObjectID)
	return id.Hex()
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

func Register(username string, password []byte, groups []string) (string, error) {
	defer func() {
			for i := range password {
			password[i] = 'A'
		}
	}()

	if !okUsername(username) {
		return "", errors.New("Invalid username")
	}

	if Lookup(username) != nil {
		return "", errors.New("Username already exists")
	}

	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	user := &createUser{
		Groups: groups,
		PasswordHash: hash,
		Username: username,
	}

	id := Insert(user)
	return id, nil
}

func Login(username, password string) (*User, error) {
	u := Lookup(username)
	if u == nil {
		return nil, nil
	}

	err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password))
	if err != nil {
		return nil, err
	}

	return u, nil
}

func Delete(username string) (int64, error) {
	c := collection()
	ctx, cancel := timeout(5)
	defer cancel()
	filter := bson.D{{Key: "username", Value: username}}
	result, err := c.DeleteOne(ctx, filter)
	return result.DeletedCount, err
}

func List() ([]User, error) {
	c := collection()
	ctx, cancel := timeout(5)
	defer cancel()
	filter := bson.D{}
	opts := options.Find().SetSort(bson.D{{Key: "name", Value: 1}})
	result, err := c.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	users := []User{}
	err = result.All(ctx, &users)
	return users, nil
}
