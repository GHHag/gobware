package gobware

import (
	"net/http"
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

//var middlewareConfig MiddlewareConfig = MiddlewareConfig{}

/*type MiddlewareHandlerFunc func(http.ResponseWriter, *http.Request)
//type MiddlewareHandlerFunc func(http.HandlerFunc) (http.HandlerFunc)
//type MiddlewareFunc func(*http.Request)

func(f MiddlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request){
	//middlewareConfig.RunChain(r)
	fmt.Println("\nLITTLE MIDDLEWARE")
	f(w, r)
}*/

/*func(f MiddlewareFunc) handleMiddleware(r *http.Request){
	f(r)
}*/

///////////////////////////////////////////////////////////////////

// Explore example use cases of this interface and if it is needed at all
type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
	runMiddleware(*http.Request)
}

type HandlerAdapter struct {
	handler http.Handler
	configuration *Configuration
}

// Should func also return error?
func NewHandlerAdapter(handler http.Handler, configuration *Configuration) (*HandlerAdapter){
	return &HandlerAdapter{
		handler: handler,
		configuration: configuration,
	}
}

// Should func also return error?
func(h *HandlerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request){
	pass := h.runMiddleware(r)
	if pass {
		h.handler.ServeHTTP(w, r)
	}
}

// Should func also return error?
func(h *HandlerAdapter) runMiddleware(r *http.Request) (bool){
	return h.configuration.RunChain(r)
}