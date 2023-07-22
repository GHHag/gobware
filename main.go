package main

import(
	"fmt"
	"net/http"
	"github.com/GHHag/gobware.git/gobware"
)

func main(){
	data := map[string]interface{}{
		"field": "value",
	}
	algo := gobware.KekwAlgorithm{}
	token := gobware.CreateToken("secret", "1234", data, algo)
	fmt.Println(gobware.CheckExpiration(token))
	//algo.Algorithm(&token, true)
	fmt.Println(token.Encoded)

	http.HandleFunc("/test", test)	
	
	http.CanonicalHeaderKey("/test")
	
	http.ListenAndServe(":6200", nil)
}

func test(w http.ResponseWriter, r *http.Request){
	fmt.Println("test")
	//fmt.Println(r.CanonicalHeaderKey())
}