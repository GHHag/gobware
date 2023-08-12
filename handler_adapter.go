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

func GenerateToken(requestToken RequestToken, config *Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(config.tokenDuration)

			token, err := requestToken(r, expires, NewToken)
			if  token != nil && err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.accessTokenKey, token, expires))

			hf(w, r)
		}
	}
}

func GenerateTokenPair(requestTokenPair RequestTokenPair, config *Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(config.tokenDuration)

			token, refreshToken, err := requestTokenPair(r, expires, NewTokenPair)
			if  token != nil && err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.accessTokenKey, token, expires))
			http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.refreshTokenKey, refreshToken, expires))

			hf(w, r)
		}
	}
}

// Move function to token.go?
func AttemptTokenExchange(accessTokenCookie http.Cookie, refreshTokenCookie http.Cookie, expires time.Time) (*string, *string, error) {
	validated, _, err := VerifyToken(refreshTokenCookie.Value)
	if validated && err == nil {
		accessToken, refreshToken, err := ExchangeTokens(accessTokenCookie.Value, refreshTokenCookie.Value, expires)

		return accessToken, refreshToken, err
	} else {
		return nil, nil, err
	}
}

func CheckToken(config *Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			accessTokenCookie, err := r.Cookie(config.accessTokenKey)
			if accessTokenCookie == nil || err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			var validated bool
			validated, _, err = VerifyToken(accessTokenCookie.Value) // Create new function to enable verification that token belongs to user
			if !validated || err != nil {
				refreshTokenCookie, err := r.Cookie(config.refreshTokenKey)
				if refreshTokenCookie != nil && err == nil {
					expires := time.Now().Add(config.tokenDuration)
					accessToken, refreshToken, err := AttemptTokenExchange(*accessTokenCookie, *refreshTokenCookie, expires)
					if accessToken != nil && refreshToken != nil && err == nil {
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.accessTokenKey, accessToken, expires))
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.refreshTokenKey, refreshToken, expires))
					} else {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				} else{
					w.WriteHeader(http.StatusForbidden)
					return
				}
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

			accessTokenCookie, err := r.Cookie(config.accessTokenKey)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}	

			var validated bool
			var accessToken *Token
			validated, accessToken, err = VerifyToken(accessTokenCookie.Value)
			if !validated || err != nil {
				refreshTokenCookie, err := r.Cookie(config.refreshTokenKey)
				if refreshTokenCookie != nil && err == nil {
					expires := time.Now().Add(config.tokenDuration)
					accessToken, refreshToken, err := AttemptTokenExchange(*accessTokenCookie, *refreshTokenCookie, expires)
					if accessToken != nil && refreshToken != nil && err == nil {
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.accessTokenKey, accessToken, expires))
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.refreshTokenKey, refreshToken, expires))
					} else {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				} else{
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			access := config.accessControlList.CheckAccess(
				accessToken.Data[config.roleKey], url, httpMethod,
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