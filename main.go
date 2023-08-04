package main

import(
	"net/http"
	"log"
	"time"
	"crypto/sha256"
	"fmt"
	"github.com/GHHag/gobware.git/gobware"
)

// "ENV" VARIABLES
var pepper string = "le pepper"
var tokenName string = "auth"
var expirationTime time.Duration = time.Hour
var roleKey string = "userRole"

// Move to file/template that configurates package settings
func createACLRules() (*gobware.ACL){
	ACL := gobware.NewACL()
	ACL.AddACLRule("user", "/request-token", []string {"GET"})
	ACL.AddACLRule("user", "/request-resource", []string {"GET"})
	ACL.AddACLRule("user", "/request-another-resource", []string {"GET", "POST", "PUT"})
	ACL.AddACLRule(gobware.NO_CONSTRAINT, "/request-token", []string {"GET"})
	ACL.AddACLRule(gobware.NO_CONSTRAINT, "/request-token", []string {"POST"})
	ACL.AddACLRule(gobware.NO_CONSTRAINT, "/request-resource", []string {"GET"})

	return ACL
}

// Move to file/template that configurates package settings
func createSecurityChain(ACL *gobware.ACL) (*gobware.Configuration){
	securityConfig := gobware.NewConfiguration(ACL, roleKey, tokenName)
	securityConfig.AddChainLink(securityConfig.CheckToken)
	securityConfig.AddChainLink(securityConfig.CheckAuthorization)

	return securityConfig
}

func main(){
	secretizeData()

	// User defined types: gobware.ACL, gobware.Configuration
	ACL := createACLRules()
	config := createSecurityChain(ACL)

	// Request that creates token (ex user login in application context)
	//http.HandleFunc("/request-token", requestToken)
	//http.HandleFunc("/request-token", gobware.Notify(requestToken))
	http.HandleFunc("/request-token", gobware.Notify()(requestToken))

	//http.HandleFunc("/request-resource", requestResource)
	http.HandleFunc("/request-resource", gobware.CheckToken(requestResource, config))
	
	http.HandleFunc("/request-another-resource", requestAnotherResource)
	
	handler := gobware.NewHandlerAdapter(http.DefaultServeMux, config) //***
	log.Fatal(http.ListenAndServe(":6200", handler)) //***
	
	//http.ListenAndServeTLS(":6200", certFile, keyFile, handler)
}

func requestToken(w http.ResponseWriter, r *http.Request){
	data := map[string] string{
		roleKey: "user",
		//roleKey: gobware.NO_CONSTRAINT,
	}

	token, err := gobware.NewToken("someUserId", data)

	if  token != nil && err != nil {
		panic(err)
	}

	cookie := http.Cookie{
		Name: tokenName,
		Value: *token,
		Expires: time.Now().Add(expirationTime),
		HttpOnly: true,
		Secure: true,
		SameSite: http.SameSiteStrictMode, // What is this?
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

func secretizeData(){
	algo := sha256.Sum256
	data := "secret data"
	secretData := []byte(data)
	salt, err := gobware.GenerateSalt(32)
	if err != nil {
		panic(err)
	}
	hash := gobware.HashData(algo, secretData, salt, []byte(pepper))

	fmt.Println(hash)
	fmt.Println(gobware.VerifyData(algo, hash, salt, []byte("pepper"), []byte(data)))
	fmt.Println(gobware.VerifyData(algo, hash, salt, []byte(pepper), []byte("")))
	fmt.Println(gobware.VerifyData(algo, hash, salt, []byte(pepper), []byte("secretdata")))
	fmt.Println(gobware.VerifyData(algo, hash, salt, []byte(pepper), []byte("secret data")))
	fmt.Println(gobware.VerifyData(algo, hash, salt, []byte("le pepper"), []byte("secret data")))
	fmt.Println(gobware.VerifyData(algo, hash, salt, []byte(pepper), []byte(data)))
}