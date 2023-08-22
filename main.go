package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	//echojwt "github.com/labstack/echo-jwt/v4"
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

type jwtCustomClaims struct {
	Username  string `json:"name"`
	Groups []string   `json:"groups"`
	jwt.RegisteredClaims
}

type pageMetadata struct {
	accessGroup string
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

func getClaims(c echo.Context) (*jwtCustomClaims, error) {
	cookie, err := c.Cookie("auth")
	if err != nil || cookie == nil {
		return nil, nil
	}
	token, err := jwt.ParseWithClaims(cookie.Value, &jwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate that the algorithm is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return mySecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*jwtCustomClaims)
	return claims, nil
}

func auth(username, password string) (*jwtCustomClaims, error) {
	// Unauthorized error
	if username != "jon" || password != "shhh!" {
		return nil, echo.ErrUnauthorized
	}
	// Set custom claims
	claims := &jwtCustomClaims{
		username,
		[]string{
			AdminGroup,
			UserGroup,
		},
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}
	return claims, nil
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	claims, err := auth(username, password)
	if err != nil {
		return err
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//TODO: use actual secret
	t, err := token.SignedString(mySecret)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
        Name:     "auth",
        Value:    t,
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }

	c.SetCookie(cookie)
	return c.Redirect(http.StatusSeeOther, "/")
}

func logout(c echo.Context) error {
	cookie, err := c.Cookie("auth")
	if err != nil {
		return err
	}
	cookie.Expires = time.Now()
	c.SetCookie(cookie)
	return c.Redirect(http.StatusSeeOther, "/")
}

func lookup(path string) string {
	redirect, ok := redirects[path]
	if ok {
		path = redirect
	}
	return strings.Trim(path, "/")
}

func visit(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	fmt.Println("claims:", claims)
	path := lookup(c.Path())
	fmt.Println("visiting:", path)
	return c.Render(http.StatusOK, path + ".html", claims)
}

/*
func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Username
	return c.String(http.StatusOK, "Welcome "+name+"!")
}
*/

func main() {

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
