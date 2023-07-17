package main

import(
	"fmt"
	"github.com/GHHag/gobware.git/gobware"
)

func main(){
	var x gobware.Token
	x.Secret = "jajaja"
	fmt.Println(x.Secret)
}