package gobware

import (
	"net/http"
	"fmt"
)

/*

Use Template package to generate/define Configuration/settings?

Define a Template for Token and use as a generic way of evaluating
the token in a ChainLink?

*/

// Link function type should accept a *http.Request param as well as
// a function that return a bool. The bool expression should be possible
// to make from the data stored in the Data field of the Token type.
type ChainLink func(*http.Request) (bool)

type Configuration struct {
	chain []ChainLink
	accessControlList *ACL
}

func NewConfiguration(chain []ChainLink, ACL *ACL) (*Configuration){
	return &Configuration{
		chain: chain,
		accessControlList: ACL,
	}
}

func(config *Configuration) AddChainLink(chainLink ChainLink){
	config.chain = append(config.chain, chainLink)
}

func(config *Configuration) RunChain(r *http.Request) (bool){
	for _, chainLink := range config.chain {
		pass := chainLink(r)
	
		if !pass {
			return false
		}
	}

	return true
}

func(config *Configuration) CheckToken(r *http.Request) (bool){
	//evaluated := l.evaluate()
	/*fmt.Println("")
	fmt.Println("CheckToken")
	fmt.Println(*r)*/

	return true
}

func(config *Configuration) CheckAuth(r *http.Request) (bool){
	url := r.URL.Path
	httpMethod := r.Method

	// If ACL for the url + method is allowed for visitor: return true
	if url == "/request-token" {
		return true
	}
	
	cookie, err := r.Cookie("auth")
	if err != nil {
		return false
	}	

	var verified bool
	var value *Token
	//verified, cookie.Value, err = VerifyToken(cookie.Value)
	verified, value, err = VerifyToken(cookie.Value)
	if !verified || err != nil {
		return false
	}

	fmt.Println(value.Data["userRole"])

	access := config.accessControlList.CheckAccess(value.Data["userRole"], url, httpMethod)
	fmt.Println(access)

	return access
}