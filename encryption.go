package gobware

import(
	"fmt"
)

func Encrypt(token *Token){
	fmt.Println("\n%s", &token.Secret)
}

func Decrypt(token *Token)(bool){
	fmt.Println("\n%s", &token.Secret)

	return false
}

func bautaEncryption(){

}
