package gobware

import (
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
			expires := time.Now().Add(TokenDuration)

			token, err := requestToken(r, expires, NewToken)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, BakeCookie(AccessTokenKey, token, expires))

			hf(w, r)
		}
	}
}

func GenerateTokenPair(requestTokenPair RequestTokenPair) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(TokenDuration)

			token, refreshToken, err := requestTokenPair(r, expires, NewTokenPair)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, BakeCookie(AccessTokenKey, token, expires))
			http.SetCookie(w, BakeCookie(RefreshTokenKey, refreshToken, expires))

			hf(w, r)
		}
	}
}

func CheckToken() HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			accessTokenCookie, err := r.Cookie(AccessTokenKey)
			if err != nil {
				http.Error(w, "Access token not available", http.StatusForbidden)
				return
			}

			validated, accessToken, err := VerifyToken(accessTokenCookie.Value)
			if err != nil || accessToken.Data == nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if !validated {
				refreshTokenCookie, err := r.Cookie(RefreshTokenKey)
				if err != nil {
					http.Error(w, "Refresh token not available", http.StatusForbidden)
					return
				}
				expires := time.Now().Add(TokenDuration)
				refreshedAccessToken, refreshToken, err := AttemptTokenExchange(accessTokenCookie.Value, refreshTokenCookie.Value, expires)
				if err == nil {
					http.SetCookie(w, BakeCookie(AccessTokenKey, refreshedAccessToken, expires))
					http.SetCookie(w, BakeCookie(RefreshTokenKey, refreshToken, expires))
				} else {
					http.SetCookie(w, &http.Cookie{Name: AccessTokenKey, MaxAge: -1})
					http.SetCookie(w, &http.Cookie{Name: RefreshTokenKey, MaxAge: -1})
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			hf(w, r)
		}
	}
}

func CheckAccess(config Configuration) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			url := r.URL.Path
			httpMethod := r.Method

			accessTokenCookie, err := r.Cookie(AccessTokenKey)
			if err != nil {
				http.Error(w, "Access token not available", http.StatusForbidden)
				return
			}

			validated, accessToken, err := VerifyToken(accessTokenCookie.Value)
			if err != nil || accessToken.Data == nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if !validated {
				refreshTokenCookie, err := r.Cookie(RefreshTokenKey)
				if err != nil {
					http.Error(w, "Refresh token not available", http.StatusForbidden)
					return
				}
				expires := time.Now().Add(TokenDuration)
				refreshedAccessToken, refreshToken, err := AttemptTokenExchange(accessTokenCookie.Value, refreshTokenCookie.Value, expires)
				if err == nil {
					http.SetCookie(w, BakeCookie(AccessTokenKey, refreshedAccessToken, expires))
					http.SetCookie(w, BakeCookie(RefreshTokenKey, refreshToken, expires))
				} else {
					http.SetCookie(w, &http.Cookie{Name: AccessTokenKey, MaxAge: -1})
					http.SetCookie(w, &http.Cookie{Name: RefreshTokenKey, MaxAge: -1})
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			access := config.CheckAccess(accessToken.Data, url, httpMethod)
			if !access {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			hf(w, r)
		}
	}
}

func Adapt(hf http.HandlerFunc, adapters ...HandlerFuncAdapter) http.HandlerFunc {
	for _, adapter := range adapters {
		hf = adapter(hf)
	}

	return hf
}
