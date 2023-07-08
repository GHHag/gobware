package gobware

import(
	"net/http"
)

type Configuration struct {
	SecurityChain []string
}

func AddToSecurityChain(config Configuration, item string){
	append(config.SecurityChain, item)
}

func RunChain(
	config Configuration, userToken UserToken, 
	*r http.RequestHandler, *w http.ResponseWriter
){

}