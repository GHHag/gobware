package main

import(
	"net/http"
	//"encoding/json"
	//"fmt"
	"time"
	"github.com/GHHag/gobware.git/gobware"
)

// "ENV" VARIABLES
var secret string = "SECRET"
var salt string = "SALT"
var tokenName string = "auth"
var expirationTime time.Duration = time.Hour

func createSecurityChain(){
	//securityConfig := gobware.Configuration{}
	//append(securityConfig.SecurityChain, gobware.CheckToken)
}

func main(){
	// Request that creates token (ex user login in application context)
	http.HandleFunc("/request-token", requestToken)	

	// Request that requires valid token (ex get some private user data in application context)
	http.HandleFunc("/request-resource", requestResource)	
	
	http.HandleFunc("/request-another-resource", requestAnotherResource)	

	//http.ListenAndServe(":6200", nil)

	/*handler := &gobware.HandlerAdapter{
		Handler: http.DefaultServeMux,
		//Handler: http.NewServeMux(),
	}*/
	handler := gobware.NewHandlerAdapter() //***
	http.ListenAndServe(":6200", handler) //***

	//http.ListenAndServeTLS(":6200", certFile, keyFile, handler)

	//x := gobware.MiddlewareHandlerFunc
	//http.ListenAndServe(":6200", gobware.MiddlewareHandlerFunc)
}

func requestToken(w http.ResponseWriter, r *http.Request){
	data := map[string]interface{}{
		"field": "value",
	}

	token, err := gobware.CreateToken("someUserId", data)

	if err != nil {
		panic(err)
	}

	cookie := http.Cookie{
		Name: tokenName,
		Value: token,
		Expires: time.Now().Add(expirationTime),
		HttpOnly: true,
		Secure: true,
	}

	http.SetCookie(w, &cookie)
	
	w.WriteHeader(http.StatusOK)
}

func requestResource(w http.ResponseWriter, r *http.Request){
	//cookie, err := r.Cookie(tokenName)
	//fmt.Println(cookie)
	//var requestVerified bool

	//requestVerified, cookie.Value, err = gobware.VerifyToken(cookie.Value)
	//fmt.Println(requestVerified)
	/*if requestVerified && err != nil {
		panic(err)
	}

	if err != nil {
		w.Write([]byte("Cookie not found"))
	} else {
		value := cookie.Value
		w.Write([]byte(value))
	}*/

	w.Write([]byte("Resource"))
}

func requestAnotherResource(w http.ResponseWriter, r *http.Request){
	/*cookie, err := r.Cookie(tokenName)
	//fmt.Println(cookie)
	var requestVerified bool

	requestVerified, cookie.Value, err = gobware.VerifyToken(cookie.Value)
	//fmt.Println(requestVerified)
	if requestVerified && err != nil {
		panic(err)
	}

	if err != nil {
		w.Write([]byte("Cookie not found"))
	} else {
		value := cookie.Value
		w.Write([]byte(value))
	}*/

	w.Write([]byte("Another resource"))
}