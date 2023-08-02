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

// Make ChainLink an http.Handler adapter?
type ChainLink func(*http.Request) bool

type Configuration struct {
	chain []ChainLink
	accessControlList *ACL
	roleKey string
	tokenKey string
}

func NewConfiguration(ACL *ACL, roleKey string, tokenKey string) *Configuration{
	return &Configuration{
		chain: []ChainLink{},
		accessControlList: ACL,
		roleKey: roleKey,
		tokenKey: tokenKey,
	}
}

func(config *Configuration) AddChainLink(chainLink ChainLink){
	config.chain = append(config.chain, chainLink)
}

// Run ChainLink functions concurrent?
func(config *Configuration) RunChain(r *http.Request) bool{
	for _, chainLink := range config.chain {
		// How to implement functionality for one call extracting/returning
		// a resource needed by the next chainLink function?
		pass := chainLink(r)
	
		if !pass {
			return false
		}
	}

	return true
}

// Can cookie be verified and extracted in this method, then passed to
// sequential method/function calls?
func(config *Configuration) CheckToken(r *http.Request) bool{
	url := r.URL.Path
	httpMethod := r.Method

	cookie, err := r.Cookie(config.tokenKey)
	if err != nil {
		access := config.accessControlList.CheckAccess(
			// Replace literal with constant defined in some approriate place
			"unconstrained", url, httpMethod,
		)
		return access
	}	

	var verified bool
	verified, _, err = VerifyToken(cookie.Value)

	return verified
}

func(config *Configuration) CheckAuthorization(r *http.Request) bool{
	url := r.URL.Path
	httpMethod := r.Method

	cookie, err := r.Cookie(config.tokenKey)
	if err != nil {
		access := config.accessControlList.CheckAccess(
			"unconstrained", url, httpMethod,
		)
		return access
	}	

	var verified bool
	var token *Token
	verified, token, err = VerifyToken(cookie.Value)
	if !verified || err != nil {
		return false
	}

	access := config.accessControlList.CheckAccess(
		token.Data[config.roleKey], url, httpMethod,
	)

	return access
}

func(config *Configuration) EventSubscribe (r *http.Request) bool{
	// Some event subscription function
	// Perhaps should not be defined as a method of the Configuration type?

	return false
}