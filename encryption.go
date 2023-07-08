package gobware

import(
	"fmt"
)

type IAlgorithm Interface {
	secret string
	algorithm func
}

type HMAC256 implements IAlgorithm{} 
type SHA256 implements IAlgorithm{} 

func Encrypt(token *Token)(*Token){
	fmt.Println("\n%s", &token.Secret)

	return &token
}

func Decrypt(token *Token)(*Token){
	fmt.Println("\n%s", &token.Secret)

	return &token
}

func bautaEncryption(){

}
