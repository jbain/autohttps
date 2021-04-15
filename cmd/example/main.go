package main

import (
	"github.com/jbain/autohttps"
	"net/http"
)
func main() {
	http.HandleFunc( "/", func( res http.ResponseWriter, req *http.Request ) {
		res.WriteHeader(200)

	} )

	s := &autohttps.Server{}
	s.Addr = "127.0.0.1:8443"
	s.ListenAndServe()
}

