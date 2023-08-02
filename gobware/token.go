package gobware

import (
	"encoding/base64"
	"encoding/json"
	"crypto/hmac"
	"crypto/sha256"
)

var secret = "SECRET"

type Token struct {
	UserId string `json:"userId"`
	Data map[string] string `json:"data"`
}

func(token *Token) encode() ([]byte, error) {
	encodedToken, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	return encodedToken, nil
}

func(token *Token) decode(encodedToken []byte) error {
	err := json.Unmarshal(encodedToken, token)
	if err != nil {
		return err
	}
	
	return nil
}

type signedToken struct {
	Signature []byte `json:"signature"`
	Data []byte `json:"data"`
}

func(signedToken *signedToken) encode() (string, error) {
	encodedSignedToken, err := json.Marshal(signedToken)
	if err != nil {
		return "", nil
	}

	return base64.URLEncoding.EncodeToString(encodedSignedToken), nil
}

func(signedToken *signedToken) decode(encodedSignedToken string) error {
	decodedSignedToken, err := base64.URLEncoding.DecodeString(encodedSignedToken)
	if err != nil {
		return err
	}

	err = json.Unmarshal(decodedSignedToken, signedToken)
	if err != nil {
		return err
	}

	return nil
}

func(signedToken *signedToken) sign() {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedToken.Data))
	signedToken.Signature = []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func(signedToken *signedToken) verify() bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signedToken.Data)

	expected := []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	return hmac.Equal(signedToken.Signature, expected)
}

// Return string or *string here?
func NewToken(userId string, data map[string] string) (string, error) {
	token := Token{
		UserId: userId,
		Data: data,
	}

	var err error

	signedToken := signedToken{}
	signedToken.Data, err = token.encode()
	if err != nil {
		return "", err
	}

	signedToken.sign()

	encodedSignedToken, err := signedToken.encode()
	if err != nil {
		return "", err
	}

	return encodedSignedToken, nil
}

func VerifyToken(encodedSignedToken string) (bool, *Token, error) {
	decodedSignedToken := signedToken{}

	err := decodedSignedToken.decode(encodedSignedToken)
	if err != nil {
		return false, &Token{}, err
	}

	check := decodedSignedToken.verify()
	//decodedToken := Token{}
	var decodedToken Token
	decodedToken.decode(decodedSignedToken.Data)

	return check, &decodedToken, nil
}

/*func(token Token) Validate(algo TokenAlgorithm)(Token){
	algo.Decrypt(&token)

	return token
}

func(token Token) Verify(config Configuration, w http.ResponseWriter, r *http.Request){
	config.RunChain(&token, w, r)
}*/