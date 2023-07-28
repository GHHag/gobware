package gobware

import(
	"net/http"
)

/*

Use Template package to generate/define Configuration/settings?

*/

//type Link func(*Token)(bool)
type Link func(*http.Request)

type Configuration struct {
	SecurityChain []Link
}

/*func AddToSecurityChain(config Configuration, link Link){
//func AddToSecurityChain(config Configuration, link Link, token *Token, w http.ResponseWriter, r *http.Request){
	append(config.SecurityChain, link)
}*/

/*func(config Configuration) RunChain(token *Token, w http.ResponseWriter, r *http.Request){
	for _, link := range config.SecurityChain {
		link(token)
	}
}*/

func(config Configuration) RunChain(r *http.Request){
	for _, link := range config.SecurityChain {
		link(r)
	}
}