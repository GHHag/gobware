package main

import(
	"fmt"
	"net/http"
	//"encoding/json"
	"github.com/GHHag/gobware.git/gobware"
)

// "ENV" VARIABLES
var secret string = "SECRET"
var salt string = "SALT"

func main(){
	// CONFIGURATION/SECURITY CHAIN
	//securityConfig := gobware.Configuration{}
	//append(securityConfig.SecurityChain, gobware.CheckToken)

	//fmt.Println(gobware.CheckExpiration(token))
	//fmt.Println(token.Encoded)
	//fmt.Println(token.Data)

	http.HandleFunc("/test", test)	
	http.HandleFunc("/request-token", requestToken)	
	
	http.CanonicalHeaderKey("/test")
	
	http.ListenAndServe(":6200", nil)
}

func requestToken(w http.ResponseWriter, r *http.Request){
	data := map[string]interface{}{
		"field": "value",
	}

	algo := gobware.KekwAlgorithm{}
	token := gobware.CreateToken(secret, salt, data, algo)
	encodedToken := token.Encode(salt)
	fmt.Println(token)

	w.Header().Set("Authorization", encodedToken)

	w.WriteHeader(http.StatusOK)
}

func test(w http.ResponseWriter, r *http.Request){
	fmt.Println("test")
	//fmt.Println(r.CanonicalHeaderKey())
}