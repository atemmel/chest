package main

import (
	"net/http"
	"text/template"
)

func main() {
	http.Handle("/static/", http.FileServer(http.Dir("./")))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		view := template.Must(template.ParseFiles("index.html"))
		view.Execute(w, nil)
	})

	http.ListenAndServe(":8080", nil)
}
