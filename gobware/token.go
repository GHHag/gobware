package gobware

import(
	"net/http"
)

type Token struct {
	Secret string `json:"secret"`
	UserId string `json:"userId"`
	Expires int `json:"expires"`
	Encoded bool `json:"encoded"`
	Data map[string]interface{} `json:"data"`
}

//func Create(secret string, userId string, expires int, data map[string]interface{}, algo TokenAlgorithm)(*Token){
func Create(secret string, userId string, expires int, data map[string]interface{}, algo TokenAlgorithm)(*Token){
	token := Token{
		Secret: secret,
		UserId: userId,
		Expires: expires,
		Encoded: false,
		Data: data,
	}

	algo.Encrypt(&token)

	return &token
}

func Validate(token *Token, algo TokenAlgorithm)(*Token){
	algo.Decrypt(token)

	return token
}

func Verify(token *Token, config Configuration, w http.ResponseWriter, r *http.Request){
	config.RunChain(token, w, r)
}

func GetData(token *Token)(bool, map[string]interface{}){
	return token.Encoded, token.Data
}