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
	Chain []ChainLink
}

func(config *Configuration) AddChainLink(chainLink ChainLink){
	config.Chain = append(config.Chain, chainLink)
}

func(config *Configuration) RunChain(r *http.Request){
	for _, chainLink := range config.Chain {
		chainLink(r)
		//chainLink.runChainLink(r)
	}
}

func CheckToken(r *http.Request) (bool){
	//evaluated := l.evaluate()
	fmt.Println("CheckToken")

	return true
}

func CheckAuth(r *http.Request) (bool){
	fmt.Println("CheckAuth")

	return false
}