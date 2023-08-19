package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	//echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var mySecret = []byte("secret")

type jwtCustomClaims struct {
	Username  string `json:"name"`
	Groups []string   `json:"groups"`
	jwt.RegisteredClaims
}

type renderer struct {
	templates *template.Template
	hotReload bool
}

func (r *renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if !r.hotReload {
		return r.templates.ExecuteTemplate(w, name, data)
	}

	tpl, err := template.ParseFiles("template/" + name)
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

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Unauthorized error
	if username != "jon" || password != "shhh!" {
		return echo.ErrUnauthorized
	}

	// Set custom claims
	claims := &jwtCustomClaims{
		username,
		[]string{
			"admin",
			"user",
		},
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
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

func index(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	fmt.Println("claims:", claims)
	return c.Render(http.StatusOK, "index.html", claims)
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Username
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func main() {
	e := echo.New()
	e.Renderer = &renderer{
		templates: template.Must(template.ParseGlob("template/*.html")),
		hotReload: true,
	}

	// Middleware
	middleware.DefaultLoggerConfig.Format = 
		"${time_rfc3339} ${method}: ${uri} ${error}\n"
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/", index)
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
