package gobware

import (
	"net/http"
)

//type Link func(*http.Request)

type Middleware interface{
	RunChain(*http.Request)
}

type MiddlewareConfig struct {
	Chain []Link
}

func(middlewareConfig *MiddlewareConfig) RunChain(*http.Request){

}