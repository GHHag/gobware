package gobware

import (
	"net/http"
)

/*

Use Template package to generate/define Configuration/settings?

Define a Template for Token and use as a generic way of evaluating
the token in a ChainLink?

*/

type ChainLink func(*http.Request) bool

type Configuration struct {
	chain []ChainLink
	accessControlList *ACL
	roleKey string
	tokenKey string
}

func NewConfiguration(ACL *ACL, roleKey string) *Configuration {
	return &Configuration{
		chain: []ChainLink{},
		accessControlList: ACL,
		roleKey: roleKey,
		tokenKey: CookieBaker.tokenKey,
	}
}

func(config *Configuration) AddChainLink(chainLink ChainLink) {
	config.chain = append(config.chain, chainLink)
}

// Run ChainLink functions concurrent?
func(config *Configuration) RunChain(r *http.Request) bool {
	for _, chainLink := range config.chain {
		pass := chainLink(r)
	
		if !pass {
			return false
		}
	}

	return true
}