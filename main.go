package main

import(
	"net/http"
	//"encoding/json"
	"fmt"
	"time"
	"github.com/GHHag/gobware.git/gobware"
)

// "ENV" VARIABLES
//var secret string = "SECRET" // secret is defined in token.go, should be env var
var salt string = "SALT"
var tokenName string = "auth"
var expirationTime time.Duration = time.Hour

func createSecurityChain() (gobware.Configuration){
	var securityChain []gobware.ChainLink	

	securityConfig := gobware.Configuration{
		Chain: securityChain,
	}
	securityConfig.AddChainLink(gobware.CheckToken)
	securityConfig.AddChainLink(gobware.CheckAuth)

	return securityConfig
}

func createACLRules() (gobware.ACL){
	acl := gobware.ACL{
		Roles: make(map[string]gobware.Role),
	}

	acl.NewACLRule("visitor", "/request-token", []string {"GET"})
	acl.NewACLRule("user", "/request-resource", []string {"GET"})
	acl.NewACLRule("user", "/request-another-resource", []string {"GET", "POST", "PUT"})
	acl.NewACLRule("visitor", "/request-token", []string {"POST"})

	fmt.Println(acl)

	return acl
}

func main(){
	config := createSecurityChain()

	acl := createACLRules()
	access := acl.CheckAccess("visitor", "/request-token", "POST")
	fmt.Println(access)
	access = acl.CheckAccess("visitor", "/request-token", "GET")
	fmt.Println(access)
	access = acl.CheckAccess("visitor", "/request-resource", "GET")
	fmt.Println(access)

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
	handler := gobware.NewHandlerAdapter(http.DefaultServeMux, config) //***
	http.ListenAndServe(":6200", handler) //***

	//http.ListenAndServeTLS(":6200", certFile, keyFile, handler)

	//x := gobware.MiddlewareHandlerFunc
	//http.ListenAndServe(":6200", gobware.MiddlewareHandlerFunc)
}

func requestToken(w http.ResponseWriter, r *http.Request){
	data := map[string]interface{}{
		"userId": "value",
		"userRole": "value",
	}

	token, err := gobware.NewToken("someUserId", data)

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