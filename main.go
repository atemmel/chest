package main

import (
	"encoding/gob"
	"errors"
	"html/template"
	"io"
	"net/http"
	"os"
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
	"/profile": {
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

type renderState struct {
	User *User
	Path string
	Entries []fileEntry
	File *fileEntry
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
	u, err := authenticate(c)
	if err != nil {
		return err
	}
	if u == nil {
		return c.NoContent(http.StatusForbidden)
	}
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

func forbidden(c echo.Context) (*User, error) {
	u, err := authenticate(c)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, c.NoContent(http.StatusForbidden)
	}
	return u, nil
}

func upload(c echo.Context) error {
	u, err := forbidden(c)
	if err != nil {
		return err
	}
	r := c.Request()
	const max = 5_368_709_120
	err = r.ParseMultipartForm(max)
	if err != nil {
		return err
	}

	//TODO: validate group is ok
	group := r.PostFormValue("group")
	_ = group
	_ = u

	parts := r.MultipartForm.File["file"]
	//TODO: make sure name is cleaned 
	name := parts[0].Filename

	file, err := os.Create(path.Join("files", name))
	if err != nil {
		return err
	}
	defer file.Close() //TODO: handle error

	for _, part := range parts {
		p, err := part.Open()
		if err != nil {
			return err
		}
		defer p.Close() //TODO: handle error
		bytes, err := io.ReadAll(p)
		if err != nil {
			return err
		}
		_, err = file.Write(bytes)
		if err != nil {
			return err
		}
	}
	return c.Redirect(http.StatusSeeOther, "/upload")
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

	entries, file := readFiles(c.Path())

	state := &renderState{
		User: user,
		Path: c.Path(),
		Entries: entries,
		File: file,
	}

	path := lookupRequest(c.Path())
	return c.Render(http.StatusOK, path + ".html", state)
}

func files(c echo.Context) error {
	user, err := forbidden(c)
	if err != nil {
		return err
	}

	path := c.Request().URL.EscapedPath()[1:]
	entries, file := readFiles(path)

	state := &renderState{
		User: user,
		Path: path,
		Entries: entries,
		File: file,
	}

	return c.Render(http.StatusOK, "index.html", state)
}

func main() {
	gob.Register(&sessionData{})
	Register("asdf", "qwer", []string{"admin", "user", "any"})

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
	e.GET("/files/*", files);
	e.POST("/login", login)
	e.POST("/logout", logout)
	e.POST("/upload", upload)

	e.Logger.Fatal(e.Start(":8080"))
}
