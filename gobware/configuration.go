package gobware

import(
	"net/http"
)


type Configuration struct {
	SecurityChain []func(*Token, http.ResponseWriter, *http.Request)
}

//func AddToSecurityChain(config Configuration, item func()){
/*func AddToSecurityChain(config Configuration, item func(), token *Token, w http.ResponseWriter, r *http.Request){
	append(config.SecurityChain, item(token, w, r))
}*/

func (config Configuration) RunChain(token *Token, w http.ResponseWriter, r *http.Request){
	for _, link := range config.SecurityChain {
		//token = link(token, w, r)
		link(token, w, r)
	}
}