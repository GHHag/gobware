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

func GenerateToken(tokenRequester TokenRequester, adaptToken bool) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(tokenDuration)

			token, err := tokenRequester.RequestToken(r, expires, NewToken)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, BakeCookie(accessTokenKey, token, expires))

			if adaptToken {
				r.AddCookie(BakeCookie(accessTokenKey, token, expires))
			}

			hf(w, r)
		}
	}
}

func GenerateTokenPair(tokenPairRequester TokenPairRequester, adaptTokens bool) HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expires := time.Now().Add(tokenDuration)

			token, refreshToken, err := tokenPairRequester.RequestTokenPair(r, expires, NewTokenPair)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, BakeCookie(accessTokenKey, token, expires))
			http.SetCookie(w, BakeCookie(refreshTokenKey, refreshToken, expires))

			if adaptTokens {
				r.AddCookie(BakeCookie(accessTokenKey, token, expires))
				r.AddCookie(BakeCookie(refreshTokenKey, refreshToken, expires))
			}

			hf(w, r)
		}
	}
}

func CheckToken() HandlerFuncAdapter {
	return func(hf http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			accessTokenCookie, err := r.Cookie(accessTokenKey)
			if err != nil {
				http.Error(w, "Access token not available", http.StatusBadRequest)
				return
			}

			validated, accessToken, err := VerifyToken(accessTokenCookie.Value)
			if err != nil || accessToken.Data == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if !validated {
				refreshTokenCookie, err := r.Cookie(refreshTokenKey)
				if err != nil {
					http.Error(w, "Refresh token not available", http.StatusBadRequest)
					return
				}
				expires := time.Now().Add(tokenDuration)
				refreshedAccessToken, refreshToken, err := AttemptTokenExchange(accessTokenCookie.Value, refreshTokenCookie.Value, expires)
				if err == nil {
					http.SetCookie(w, BakeCookie(accessTokenKey, refreshedAccessToken, expires))
					http.SetCookie(w, BakeCookie(refreshTokenKey, refreshToken, expires))
				} else {
					http.SetCookie(w, &http.Cookie{Name: accessTokenKey, MaxAge: -1})
					http.SetCookie(w, &http.Cookie{Name: refreshTokenKey, MaxAge: -1})
					w.WriteHeader(http.StatusUnauthorized)
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

			accessTokenCookie, err := r.Cookie(accessTokenKey)
			if err != nil {
				http.Error(w, "Access token not available", http.StatusBadRequest)
				return
			}

			validated, accessToken, err := VerifyToken(accessTokenCookie.Value)
			if err != nil || accessToken.Data == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if !validated {
				refreshTokenCookie, err := r.Cookie(refreshTokenKey)
				if err != nil {
					http.Error(w, "Refresh token not available", http.StatusBadRequest)
					return
				}
				expires := time.Now().Add(tokenDuration)
				refreshedAccessToken, refreshToken, err := AttemptTokenExchange(accessTokenCookie.Value, refreshTokenCookie.Value, expires)
				if err == nil {
					http.SetCookie(w, BakeCookie(accessTokenKey, refreshedAccessToken, expires))
					http.SetCookie(w, BakeCookie(refreshTokenKey, refreshToken, expires))
				} else {
					http.SetCookie(w, &http.Cookie{Name: accessTokenKey, MaxAge: -1})
					http.SetCookie(w, &http.Cookie{Name: refreshTokenKey, MaxAge: -1})
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}

			access := config.CheckAccess(accessToken.Data, url, httpMethod)
			if !access {
				w.WriteHeader(http.StatusUnauthorized)
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
