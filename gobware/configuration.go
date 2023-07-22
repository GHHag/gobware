package gobware

import(
	"net/http"
)

type Link func(*Token, *http.Request) (bool)

type Configuration struct {
	SecurityChain []Link
}

/*func AddToSecurityChain(config Configuration, link Link){
//func AddToSecurityChain(config Configuration, link Link, token *Token, w http.ResponseWriter, r *http.Request){
	append(config.SecurityChain, link)
}*/

func (config Configuration) RunChain(token *Token, w http.ResponseWriter, r *http.Request){
	for _, link := range config.SecurityChain {
		link(token, r)
	}
}