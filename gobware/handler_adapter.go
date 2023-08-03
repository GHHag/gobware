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

// Explore example use cases of this interface and if it is needed at all
type MiddlewareHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
	runMiddleware(*http.Request)
}

type HandlerAdapter struct {
	handler http.Handler
	configuration *Configuration
}

func NewHandlerAdapter(handler http.Handler, configuration *Configuration) *HandlerAdapter{
	return &HandlerAdapter{
		handler: handler,
		configuration: configuration,
	}
}

// Should func also return error?
func(h *HandlerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request){
	h.handler.ServeHTTP(w, r)
	/*pass := h.runMiddleware(r)
	if pass {
		h.handler.ServeHTTP(w, r)
	}*/
}

// Should func also return error?
func(h *HandlerAdapter) runMiddleware(r *http.Request) bool{
	return h.configuration.RunChain(r)
}