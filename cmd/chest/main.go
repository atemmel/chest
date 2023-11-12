package main

import (
	"chest/pkg/db"
	"chest/pkg/files"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
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

var mySecret []byte

const (
	root = "/chest";
	templateDir = "templates/"
	partsDir = templateDir + "parts/"
)

type sessionData struct {
	Id string
}

var store = sessions.NewCookieStore(mySecret)

type renderer struct {
	templates *template.Template
	hotReload bool
}

type renderState struct {
	User *db.User
	Path string
	ParentPath string
	Entries []files.Entry
	File *files.Entry
}

func NewRenderer(files []string, hotReload bool) *renderer {
	parts, err := filepath.Glob(path.Join(resourceRoot, partsDir) + "/*.html")
	if err != nil {
		panic(err)
	}
	if len(parts) == 0 {
		fmt.Println("Could not find parts, exiting...")
		os.Exit(1)
	}
	pages := make([]string, 0, len(files) + len(parts))
	pages = append(pages, parts...)
	for _, f := range files {
		p := path.Join(resourceRoot, templateDir, f)
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

	parts, err := filepath.Glob(path.Join(resourceRoot, partsDir) + "/*.html")
	if err != nil {
		return err
	}
	parts = append(parts, path.Join(resourceRoot, templateDir, name))

	tpl, err := template.ParseFiles(parts...)
	if err != nil {
		return err
	}
    return tpl.ExecuteTemplate(w, name, data)
}

func authenticate(c echo.Context) (*db.User, error) {
	session, err := store.Get(c.Request(), "session")
	if err != nil {
		return nil, err
	}
	var data *sessionData
	var user *db.User
	value, ok := session.Values["user"]
	if !ok {
		return nil, nil
	}
	data, ok = value.(*sessionData)
	if !ok {
		return nil, errors.New("Illegal session state")
	}
	user = db.LookupHexId(data.Id)
	if user == nil {
		return nil, nil
	}
	return user, nil
}

func postLogin(c echo.Context) error {
	r := c.Request()
	w := c.Response().Writer

	username := c.FormValue("username")
	password := c.FormValue("password")

	user, err := db.Login(username, password)
	if err != nil {
		return err
	}

	if user == nil {
		return c.Redirect(http.StatusSeeOther, root + "/login")
	}

	session, err := store.Get(r, "session")
	if err != nil {
		return err
	}

	session.Options.MaxAge = 86400 * 7 // one week
	data := &sessionData{
		Id: user.Id.Hex(),
	}
	
	session.Values["user"] = data
	err = session.Save(r, w)
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, root + "/")
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
	return c.Redirect(http.StatusSeeOther, root + "/")
}

func forbidden(c echo.Context) (*db.User, error) {
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

	// validate group is ok
	group := r.PostFormValue("group")
	if !u.PartOf(group) {
		return c.NoContent(http.StatusForbidden)
	}

	base := r.PostFormValue("base")
	parts := r.MultipartForm.File["file"]
	//TODO: make sure name is clean(?)
	name := parts[0].Filename
	//TODO: make sure file exists
	fullpath := path.Join("files", base, name)

	file, err := os.Create(fullpath)
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

	redirect := path.Join(root, "/files", base)
	return c.Redirect(http.StatusSeeOther, redirect)
}

func mkdir(c echo.Context) error {
	u, err := forbidden(c)
	if err != nil {
		return err
	}
	r := c.Request()
	mkdirBase := r.PostFormValue("base")
	mkdirName := r.PostFormValue("name")
	mkdirReadGroup := r.PostFormValue("read-group")
	mkdirWriteGroup := r.PostFormValue("write-group")

	if !strings.HasPrefix(mkdirBase, "/files") {
		mkdirBase = "files" + mkdirBase
	}

	meta, err := files.ReadMeta(mkdirBase)
	if err != nil {
		return err
	}

	// make sure user is allowed to create
	if !u.PartOf(meta.WriteGroup) {
		return c.NoContent(http.StatusForbidden)
	}

	//TODO: make sure name does not exist
	fullPath := path.Join(mkdirBase, mkdirName)
	newPath, err := files.Mkdir(fullPath, mkdirReadGroup, mkdirWriteGroup)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusSeeOther, root + "/" + newPath)
}

func download(c echo.Context) error {
	u, err := forbidden(c)
	if err != nil {
		return err
	}
	child := c.QueryParam("path")
	if len(child) <= len(root) {
		return c.NoContent(http.StatusNotFound)

	}
	child = child[len(root)+1:]
	filename := path.Base(child)
	dir := path.Dir(child)
	meta, err := files.ReadMeta(dir)
	if err != nil {
		return err
	}

	// make sure user is allowed to download
	if !u.PartOf(meta.ReadGroup) {
		return c.NoContent(http.StatusForbidden)
	}

	return c.Attachment(child, filename)
}

func login(c echo.Context) error {
	user, _ := authenticate(c)
	if user != nil {
		return c.Redirect(http.StatusSeeOther, root + "/files")
	}
	return c.Render(http.StatusOK, "login.html", nil)
}

// produces redirect lambda
func redirect(to string) (func(echo.Context) error) {
	return func(c echo.Context) error {
		return c.Redirect(http.StatusSeeOther, to)
	}
}

// produces auth lambda
func auth(group string, proc func(*db.User, echo.Context) error) (func(echo.Context) error) {
	return func(c echo.Context) error {
		var user *db.User
		var err error

		if group == db.AnyGroup {
			goto OK
		}

		user, err = authenticate(c)
		if err != nil || user == nil {
			return c.Redirect(http.StatusSeeOther, root + "/login")
		}
		if !user.PartOf(group) {
			return c.NoContent(http.StatusForbidden)
		}

		OK:
		return proc(user, c)
	}
}

func render(template string, makeState func(*db.User, echo.Context) *renderState) (func(*db.User, echo.Context) error) {
	return func(user *db.User, c echo.Context) error {
		state := makeState(user, c)
		return c.Render(http.StatusOK, template, state)
	}
}

func defaultState(user *db.User, c echo.Context) *renderState {
	return &renderState{
		User: user,
		Path: "",
		Entries: nil,
		File: nil,
	}
}

func mkdirState(user *db.User, c echo.Context) *renderState {
	child := c.QueryParam("path")
	if child == "" {
		child = "/"
	}
	return &renderState{
		User: user,
		Path: child,
		Entries: nil,
		File: nil,
	}
}

func uploadState(user *db.User, c echo.Context) *renderState {
	child := c.QueryParam("path")
	if child == "" {
		child = "/"
	}
	return &renderState{
		User: user,
		Path: child,
		Entries: nil,
		File: nil,
	}
}

func filesState(user *db.User, c echo.Context) *renderState {
	child := c.Request().URL.EscapedPath()
	child = child[len(root) + 1:]
	parent := path.Dir(child)
	entries, file := files.ReadFiles(child)
	return &renderState{
		User: user,
		Path: root + "/" + child,
		ParentPath: root + "/" + parent,
		Entries: entries,
		File: file,
	}
}

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

var debug = false
var fsRoot = ""
var resourceRoot = ""

func init() {
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.StringVar(&fsRoot, "fs", "", "Set root of hosted filesystem")
	flag.StringVar(&resourceRoot, "res", "", "Set resource root")
	flag.Parse()
}

func main() {
	gob.Register(&sessionData{})

	{
		secret, b := os.LookupEnv("chest_cookie_secret")
		if !b {
			fmt.Println("Cookie secret not set, exiting...")
			os.Exit(1)
		}
		mySecret = []byte(secret)
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	assert(db.Connect())
	defer func() {
		assert(db.Disconnect())
	}()

	middleware.DefaultLoggerConfig.Format = 
		"${time_rfc3339} ${method}: ${uri} ${error}\n"
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	chest := e.Group("/chest")

	chest.Static("/static", resourceRoot + "/static")

	chest.GET("", redirect(root + "/files"))
	chest.GET("/", redirect(root + "/files"))
	chest.GET("/files", auth(db.UserGroup, render("index.html", filesState)))
	chest.GET("/files/*", auth(db.UserGroup, render("index.html", filesState)))
	chest.GET("/upload", auth(db.UserGroup, render("upload.html", uploadState)))
	chest.GET("/profile", auth(db.UserGroup, render("profile.html", defaultState)))
	chest.GET("/mkdir", auth(db.UserGroup, render("mkdir.html", mkdirState)));
	chest.GET("/download", download);

	chest.GET("/login", login);
	chest.POST("/login", postLogin)
	chest.POST("/logout", logout)
	chest.POST("/upload", upload)
	chest.POST("/mkdir", mkdir)

	hotReload := debug
	fmt.Println("Hot-reload is:", hotReload)

	e.Renderer = NewRenderer([]string{
		"login.html",
		"index.html",
		"upload.html",
		"profile.html",
		"mkdir.html",
	}, hotReload)

	e.Logger.Fatal(e.Start(":8080"))
}
