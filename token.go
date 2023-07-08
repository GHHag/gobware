package gobware

import(
	"net/http"
)

type Token struct {
	Secret string
	UserId string
	Expires int
	Encoded bool
	Data: interface{} // field for arbitrary data stored with the token
}

func Create(secret string, userId string, expires int)(*Token){
	token := Token{
		Secret: secret,
		UserId: userId,
		Expires: expires,
	}

	Encrypt(&token)

	return &token
}

func Validate(token *Token)(bool){
	validated := Decrypt(token)

	return validated
}

func Verify(
	token *Token, config Configuration, 
	*r http.RequestHandler, *w ResponseWriter
){
	config.RunChain(token, r, w)
}

func GetData(token *Token)(Token.Data){
	if(token.Encoded == false){
		return token.Data
	}
}
