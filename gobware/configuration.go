package gobware

import (
	"net/http"
	//"fmt"
)

/*

Use Template package to generate/define Configuration/settings?

Define a Template for Token and use as a generic way of evaluating
the token in a ChainLink?

*/

// Link function type should accept a *http.Request param as well as
// a function that return a bool. The bool expression should be possible
// to make from the data stored in the Data field of the Token type.
type ChainLink func(*http.Request) bool

type Configuration struct {
	chain []ChainLink
	accessControlList *ACL
	roleKey string
	tokenCookie string
}

func NewConfiguration(chain []ChainLink, ACL *ACL, roleKey string, tokenCookie string) *Configuration{
	return &Configuration{
		chain: chain,
		accessControlList: ACL,
		roleKey: roleKey,
		tokenCookie: tokenCookie,
	}
}

func(config *Configuration) AddChainLink(chainLink ChainLink){
	config.chain = append(config.chain, chainLink)
}

func(config *Configuration) RunChain(r *http.Request) bool{
	for _, chainLink := range config.chain {
		pass := chainLink(r)
	
		if !pass {
			return false
		}
	}

	return true
}

func(config *Configuration) CheckToken(r *http.Request) bool{
	url := r.URL.Path
	httpMethod := r.Method

	// Something with similar functionality should be run before checking if a token
	// cookie exists
	if config.accessControlList.CheckAccess("visitor", url, httpMethod) {
		return true
	}

	cookie, err := r.Cookie(config.tokenCookie)
	if err != nil {
		return false
	}	

	var verified bool
	verified, _, err = VerifyToken(cookie.Value)

	return verified
}

func(config *Configuration) CheckAuth(r *http.Request) bool{
	url := r.URL.Path
	httpMethod := r.Method

	// If ACL for the url + method is allowed for visitor: return true
	if config.accessControlList.CheckAccess("visitor", url, httpMethod) {
		return true
	}
	
	cookie, err := r.Cookie(config.tokenCookie)
	if err != nil {
		return false
	}	

	var verified bool
	var token *Token
	verified, token, err = VerifyToken(cookie.Value)
	if !verified || err != nil {
		return false
	}

	//fmt.Println(token.Data[config.roleKey])

	access := config.accessControlList.CheckAccess(
		token.Data[config.roleKey], url, httpMethod,
	)

	//fmt.Println(access)

	return access
}