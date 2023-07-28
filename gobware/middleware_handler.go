package gobware

import (
	"net/http"
	"fmt"
)

/*

From go source code:

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}

*/

var middlewareConfig MiddlewareConfig = MiddlewareConfig{}

type MiddlewareHandlerFunc func(http.ResponseWriter, *http.Request)
//type MiddlewareFunc func(*http.Request)

func(f MiddlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request){
	//middlewareConfig.RunChain(r)
	fmt.Println("\nLITTLE MIDDLEWARE")
	f(w, r)
}

/*func(f MiddlewareFunc) handleMiddleware(r *http.Request){
	f(r)
}*/

///////////////////////////////////////////////////////////////////

type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
	handleMiddleware(*http.Request)
	runMiddleware(*http.Request)
}

type HandlerAdapter struct {
	handler http.Handler
	configuration Configuration
}

func NewHandlerAdapter() (*HandlerAdapter){
	return &HandlerAdapter{
		handler: http.DefaultServeMux,
	}
}

func(h *HandlerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request){
	h.handleMiddleware(r)
	h.runMiddleware(r)
	h.handler.ServeHTTP(w, r)
}

func(h *HandlerAdapter) handleMiddleware(r *http.Request) {
	fmt.Println("\nLITTLE MIDDLEWARE")

	cookie, err := r.Cookie("auth")

	if err != nil {
		fmt.Println("Cookie not found")
	} else{
		fmt.Println(cookie)
	}
}

func(h *HandlerAdapter) runMiddleware(r *http.Request) {
	h.configuration.RunChain(r)

	/*cookie, err := r.Cookie("auth")

	if err != nil {
		fmt.Println("Cookie not found")
	} else{
		fmt.Println(cookie)
	}*/
}