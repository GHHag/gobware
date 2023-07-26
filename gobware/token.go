package gobware

import(
	"net/http"
	"time"
)

const expirationTime int64 = 3600
 
type Token struct {
	Secret string `json:"secret"`
	UserId string `json:"userId"`
	Expires int64 `json:"expires"`
	Encoded bool `json:"encoded"`
	Data map[string]interface{} `json:"data"`
}

func CreateToken(secret string, userId string, data map[string]interface{}, algo TokenAlgorithm)(Token){
//func CreateToken(secret string, userId string)(Token){
	token := Token{
		Secret: secret,
		UserId: userId,
		Expires: time.Now().Unix() + expirationTime,
		Encoded: false,
		Data: data,
	}

	algo.Encrypt(&token)

	return token
}

func(Token) Encode(salt string)(string){
	return "MOCK ENCODED JSON TOKEN OBJECT"
}

func CheckExpiration(token Token)(bool){
	return token.Expires - time.Now().Unix() < 0
}

func Validate(token Token, algo TokenAlgorithm)(Token){
	algo.Decrypt(&token)

	return token
}

func Verify(token Token, config Configuration, w http.ResponseWriter, r *http.Request){
	config.RunChain(&token, w, r)
}

func GetData(token Token)(bool, map[string]interface{}){
	return token.Encoded, token.Data
}