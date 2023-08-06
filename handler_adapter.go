package gobware

import(
	"net/http"
	"time"
)

/*

From go source code:
"
// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}
"

Adapters should not set any http headers unless returning before 
calling the HandlerFunc.

*/

type HandlerFuncAdapter func(http.HandlerFunc) http.HandlerFunc

func GenerateToken(requestToken RequestToken, duration time.Duration, config *Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(duration)

			token, err := requestToken(r, expires, NewToken)
			if  token != nil && err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			cookie := CookieBaker.BakeCookie(token, expires)
			http.SetCookie(w, cookie)

			hf(w, r)
		}
	}
}

func CheckToken(config *Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(config.tokenKey)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}	

			var verified bool
			verified, _, err = VerifyToken(cookie.Value)
			if !verified {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			hf(w, r)
		}
	}
}

func CheckAccess(config *Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			url := r.URL.Path
			httpMethod := r.Method

			cookie, err := r.Cookie(config.tokenKey)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}	

			var verified bool
			var token *Token
			verified, token, err = VerifyToken(cookie.Value)
			if !verified || err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			access := config.accessControlList.CheckAccess(
				token.Data[config.roleKey], url, httpMethod,
			)
			if !access {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			hf(w, r)
		}
	}
}

func PublishEvent() HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Publish event to subscribers
		}
	}
}

func Adapt(hf http.HandlerFunc, adapters ...HandlerFuncAdapter) http.HandlerFunc {
	for _, adapter := range adapters {
		hf = adapter(hf)
	}

	return hf
}

/////////////////////////////////////////////////7

// Explore example use cases of this interface and if it is needed at all
/*type MiddlewareHandler interface {
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
	pass := h.runMiddleware(r)
	if pass {
		h.handler.ServeHTTP(w, r)
	}
}

// Should func also return error?
func(h *HandlerAdapter) runMiddleware(r *http.Request) bool{
	return h.configuration.RunChain(r)
}*/