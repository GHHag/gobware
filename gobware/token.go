package gobware

import (
	"encoding/base64"
	"encoding/json"
	"crypto/hmac"
	"crypto/sha256"
	"time"
	"net/http"
)

var secret, _ = GenerateSalt(32)
var salt, _ = GenerateSalt(32)

var CookieBaker = CookieBakery {
	tokenKey: "auth",
	duration: time.Hour,
}

type CookieBakery struct {
	tokenKey string
	duration time.Duration
}

func(cookieBakery *CookieBakery) BakeCookie(value *string, expires time.Time) *http.Cookie {
	return &http.Cookie {
		Name: cookieBakery.tokenKey,
		Value: *value,
		Expires: expires,
		HttpOnly: true,
		Secure: true,
		SameSite: http.SameSiteStrictMode, // What is this?
	}
}

type RequestToken func(*http.Request, time.Time, CreateToken) (*string, error)
type CreateToken func(string, time.Time, map[string] string) (*string, error)

type Token struct {
	Id string `json:"id"`
	Expires time.Time
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

func(token *Token) checkExpiration() bool {
	//return token.Expiration < time.Now()
	return true
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
	mac := hmac.New(sha256.New, append(secret, salt...))
	mac.Write([]byte(signedToken.Data))
	signedToken.Signature = []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func(signedToken *signedToken) verify() bool {
	mac := hmac.New(sha256.New, append(secret, salt...))
	mac.Write(signedToken.Data)

	expected := []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	return hmac.Equal(signedToken.Signature, expected)
}

func NewToken(id string, expires time.Time, data map[string] string) (*string, error) {
	token := Token{
		Id: id,
		Expires: expires,
		Data: data,
	}

	var err error

	signedToken := signedToken{}
	signedToken.Data, err = token.encode()
	if err != nil {
		return nil, err
	}

	signedToken.sign()

	encodedSignedToken, err := signedToken.encode()
	if err != nil {
		return nil, err
	}

	return &encodedSignedToken, nil
}

func VerifyToken(encodedSignedToken string) (bool, *Token, error) {
	decodedSignedToken := signedToken{}

	err := decodedSignedToken.decode(encodedSignedToken)
	if err != nil {
		return false, nil, err
	}

	check := decodedSignedToken.verify()
	var decodedToken Token
	decodedToken.decode(decodedSignedToken.Data)

	return check, &decodedToken, nil
}