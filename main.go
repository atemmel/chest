package main

import (
	"log"
	"net/http"
	"text/template"
)

var (
	templates = map[string]string{
		"/": "template/index.html",
	}
)

func main() {
	http.Handle("/static/", http.FileServer(http.Dir("./")))

	for k, v := range templates {
		http.HandleFunc(k, func(w http.ResponseWriter, r *http.Request) {
			view := template.Must(template.ParseFiles(v))
			view.Execute(w, nil)
		})
	}


	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
