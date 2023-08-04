package gobware

import(
	"fmt"
	"net/http"
)

//type Adapter func(func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request)

func CheckToken(f func(http.ResponseWriter, *http.Request), config *Configuration) func(http.ResponseWriter, *http.Request){
	return func(w http.ResponseWriter, r *http.Request){
		url := r.URL.Path
		httpMethod := r.Method

		cookie, err := r.Cookie(config.tokenKey)
		fmt.Println(cookie)
		if err != nil {
			access := config.accessControlList.CheckAccess(
				NO_CONSTRAINT, url, httpMethod,
			)
			if !access {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("error"))
			}
		}	

		var verified bool
		verified, _, err = VerifyToken(cookie.Value)
		if !verified{
			w.Write([]byte("error"))
			w.WriteHeader(http.StatusForbidden)
		}

		w.WriteHeader(http.StatusOK)
		f(w, r)
	}
}

func Notify(f func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request){
	return func(w http.ResponseWriter, r *http.Request){
		fmt.Println("Notify")
		f(w, r)
	}
}

type Adapter func(http.Handler) http.Handler

/*func Notify(h http.Handler, f func(http.ResponseWriter, *http.Request)) http.Handler{
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	  	fmt.Println("Notify")
		f(w, r)
      	h.ServeHTTP(w, r)  
    })
}*/
/*func Notify() Adapter {
  return func(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	  fmt.Println("Notify")
      h.ServeHTTP(w, r)  
    })
  }
}*/

func Adapt(h http.Handler, adapters ...Adapter) http.Handler{
	for _, adapter := range adapters {
		h = adapter(h)
	}

	return h
}