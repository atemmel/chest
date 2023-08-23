package main

import (
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var mySecret = []byte("secret")

const (
	AdminGroup = "admin"
	UserGroup = "user"
	AnyGroup = ""

	templateDir = "templates/"
	partsDir = "templates/parts/"
)

type pageMetadata struct {
	accessGroup string
}

type sessionData struct {
	Id Id
}

var pageMetadataMap = map[string]pageMetadata {
	"/index": {
		accessGroup: AnyGroup,
	},
	"/upload": {
		accessGroup: UserGroup,
	},
}

var redirects = map[string]string {
	"/": "/index",
}

var store = sessions.NewCookieStore(mySecret)

type renderer struct {
	templates *template.Template
	hotReload bool
}

func NewRenderer(pageMetadataMap map[string]pageMetadata, hotReload bool) *renderer {
	parts, err := filepath.Glob(partsDir + "*.html")
	if err != nil {
		panic(err)
	}
	pages := make([]string, 0, len(pageMetadataMap) + len(parts))
	pages = append(pages, parts...)
	for k := range pageMetadataMap {
		p := path.Join(templateDir, k + ".html")
		pages = append(pages, p)
	}
	
	return &renderer{
		templates: template.Must(template.ParseFiles(pages...)),
		hotReload: hotReload,
	}
}

func (r *renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if !r.hotReload {
		return r.templates.ExecuteTemplate(w, name, data)
	}

	parts, err := filepath.Glob(partsDir + "*.html")
	if err != nil {
		return err
	}
	parts = append(parts, templateDir + name)

	tpl, err := template.ParseFiles(parts...)
	if err != nil {
		return err
	}
    return tpl.ExecuteTemplate(w, name, data)
}

func authenticate(c echo.Context) (*User, error) {
	session, err := store.Get(c.Request(), "session")
	if err != nil {
		return nil, err
	}
	var data *sessionData
	var user *User
	value, ok := session.Values["user"]
	if !ok {
		return nil, nil
	}
	data, ok = value.(*sessionData)
	if !ok {
		return nil, errors.New("Illegal session state")
	}
	user = LookupId(data.Id)
	if user == nil {
		return nil, nil
	}
	return user, nil
}

func login(c echo.Context) error {
	r := c.Request()
	w := c.Response().Writer

	username := c.FormValue("username")
	password := c.FormValue("password")

	user, err := Login(username, password)
	if err != nil {
		return err
	}

	session, err := store.Get(r, "session")
	if err != nil {
		return err
	}

	session.Options.MaxAge = 86400 * 7 // one week
	data := &sessionData{
		Id: user.Id,
	}
	
	session.Values["user"] = data
	err = session.Save(r, w)
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/")
}

func logout(c echo.Context) error {
	r := c.Request()
	w := c.Response().Writer
	session, err := store.Get(r, "session")
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusSeeOther, "/")
}

func lookupRequest(path string) string {
	redirect, ok := redirects[path]
	if ok {
		path = redirect
	}
	return strings.Trim(path, "/")
}

func visit(c echo.Context) error {
	user, err := authenticate(c)
	if err != nil {
		return err
	}
	fmt.Println("user:", user)
	path := lookupRequest(c.Path())
	fmt.Println("visiting:", path)
	return c.Render(http.StatusOK, path + ".html", user)
}

func main() {
	gob.Register(&sessionData{})
	Register("asdf", "qwer", []string{"admin", "user", "any"})
	fmt.Println("db:", fakeDb)

	e := echo.New()
	e.Renderer = NewRenderer(pageMetadataMap, true)

	// Middleware
	middleware.DefaultLoggerConfig.Format = 
		"${time_rfc3339} ${method}: ${uri} ${error}\n"
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	for k := range pageMetadataMap {
		e.GET(k, visit)
	}
	for k := range redirects {
		e.GET(k, visit)
	}
	e.Static("/static", "static")

	e.POST("/login", login)
	e.POST("/logout", logout)

	/*
	// Restricted group
	r := e.Group("/api")

	// Configure middleware with the custom claims type
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(jwtCustomClaims)
		},
		SigningKey: []byte("secret"),
	}
	r.Use(echojwt.WithConfig(config))
	r.GET("", restricted)
	*/

	e.Logger.Fatal(e.Start(":8080"))
}
