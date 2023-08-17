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

func GenerateToken(requestToken RequestToken) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(Config.TokenDuration)

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

func GenerateTokenPair(requestTokenPair RequestTokenPair) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(Config.TokenDuration)

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

func CheckToken() HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			accessTokenCookie, err := r.Cookie(CookieBaker.accessTokenKey)
			if accessTokenCookie == nil || err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			var validated bool
			validated, _, err = VerifyToken(accessTokenCookie.Value)
			if !validated || err != nil {
				refreshTokenCookie, err := r.Cookie(CookieBaker.refreshTokenKey)
				if refreshTokenCookie != nil && err == nil {
					expires := time.Now().Add(Config.TokenDuration)
					accessToken, refreshToken, err := AttemptTokenExchange(*accessTokenCookie, *refreshTokenCookie, expires)
					if accessToken != nil && refreshToken != nil && err == nil {
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.accessTokenKey, accessToken, expires))
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.refreshTokenKey, refreshToken, expires))
					} else {
						http.SetCookie(w, &http.Cookie{Name: CookieBaker.accessTokenKey, MaxAge: -1})
						http.SetCookie(w, &http.Cookie{Name: CookieBaker.refreshTokenKey, MaxAge: -1})
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

func CheckAccess() HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			url := r.URL.Path
			httpMethod := r.Method

			accessTokenCookie, err := r.Cookie(CookieBaker.accessTokenKey)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}	

			var validated bool
			var accessToken *Token
			validated, accessToken, err = VerifyToken(accessTokenCookie.Value)
			if !validated || err != nil {
				refreshTokenCookie, err := r.Cookie(CookieBaker.refreshTokenKey)
				if refreshTokenCookie != nil && err == nil {
					expires := time.Now().Add(Config.TokenDuration)
					accessToken, refreshToken, err := AttemptTokenExchange(*accessTokenCookie, *refreshTokenCookie, expires)
					if accessToken != nil && refreshToken != nil && err == nil {
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.accessTokenKey, accessToken, expires))
						http.SetCookie(w, CookieBaker.BakeCookie(CookieBaker.refreshTokenKey, refreshToken, expires))
					} else {
						http.SetCookie(w, &http.Cookie{Name: CookieBaker.accessTokenKey, MaxAge: -1})
						http.SetCookie(w, &http.Cookie{Name: CookieBaker.refreshTokenKey, MaxAge: -1})
						w.WriteHeader(http.StatusForbidden)
						return
					}
				} else{
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			access := Config.accessControlList.CheckAccess(accessToken.Data, url, httpMethod)
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