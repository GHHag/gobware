package main

import(
	"net/http"
	//"encoding/json"
	//"fmt"
	"time"
	"github.com/GHHag/gobware.git/gobware"
)

// "ENV" VARIABLES
//var secret string = "SECRET" // secret is defined in token.go, should be env var
var salt string = "SALT"
var tokenName string = "auth"
var expirationTime time.Duration = time.Hour

func createACLRules() (*gobware.ACL){
	ACL := gobware.NewACL()
	ACL.NewACLRule("user", "/request-token", []string {"GET"})
	ACL.NewACLRule("user", "/request-resource", []string {"GET"})
	ACL.NewACLRule("user", "/request-another-resource", []string {"GET", "POST", "PUT"})
	ACL.NewACLRule("visitor", "/request-token", []string {"GET"})
	ACL.NewACLRule("visitor", "/request-resource", []string {"GET"})
	ACL.NewACLRule("visitor", "/request-token", []string {"POST"})

	return ACL
}

func createSecurityChain(ACL *gobware.ACL) (*gobware.Configuration){
	var securityChain []gobware.ChainLink	

	securityConfig := gobware.NewConfiguration(securityChain, ACL)
	securityConfig.AddChainLink(securityConfig.CheckToken)
	securityConfig.AddChainLink(securityConfig.CheckAuth)

	return securityConfig
}

func main(){
	ACL := createACLRules()
	config := createSecurityChain(ACL)

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
	data := map[string] string{
		//"userId": "value",
		"userRole": "visitor",
		//"userRole": "user",
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
	w.Write([]byte("Resource"))
}

func requestAnotherResource(w http.ResponseWriter, r *http.Request){
	w.Write([]byte("Another resource"))
}