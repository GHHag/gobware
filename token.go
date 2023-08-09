package gobware

import (
	"fmt"
	"encoding/base64"
	"encoding/json"
	"crypto/hmac"
	"crypto/sha256"
	"time"
	"net/http"
	"os"
)

var CookieBaker = CookieBakery {
	tokenKey: "auth", // Make this an env var or define it somewhere else.
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

type CreateToken func(time.Time, map[string] string) (*string, error)
type RequestToken func(*http.Request, time.Time, CreateToken) (*string, error)
type CreateTokenPair func(time.Time, map[string] string) (*string, *string, error)
type RequestTokenPair func(*http.Request, time.Time, CreateTokenPair) (*string, *string, error)

type Token struct {
	Id string `json:"id"`
	Expires time.Time
	Data map[string] string `json:"data"`
	RefreshToken bool
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
	mac := hmac.New(sha256.New, []byte(os.Getenv(SecretKey) + os.Getenv(SaltKey)))
	mac.Write([]byte(signedToken.Data))
	signedToken.Signature = []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func(signedToken *signedToken) verify() bool {
	mac := hmac.New(sha256.New, []byte(os.Getenv(SecretKey) + os.Getenv(SaltKey)))
	mac.Write(signedToken.Data)

	expected := []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	return hmac.Equal(signedToken.Signature, expected)
}

func NewToken(expires time.Time, data map[string] string) (*string, error) {
	id, _ := GenerateId(256)
	idHash := HashData(sha256.Sum256, id, []byte(os.Getenv(SaltKey)), []byte(os.Getenv(SecretKey)))

	token := Token{
		Id: base64.StdEncoding.EncodeToString(idHash),
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

func NewTokenPair(expires time.Time, data map[string] string) (*string, *string, error) {
	id, _ := GenerateId(256)
	idHash := HashData(sha256.Sum256, id, []byte(os.Getenv(SaltKey)), []byte(os.Getenv(SecretKey)))
	encodedId := base64.StdEncoding.EncodeToString(idHash)

	token := Token{
		// Auto generate UUID, use same id for refresh token and use it to sign and verify
		// that access and refresh tokens are paired with each other
		Id: encodedId, // Salt and encrypt/sign id?
		Expires: expires,
		Data: data,
	}
	fmt.Println(token)

	var err error

	signedToken := signedToken{}
	signedToken.Data, err = token.encode()
	if err != nil {
		return nil, nil, err
	}
	signedToken.sign()

	encodedSignedToken, err := signedToken.encode()
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err := newRefreshToken(encodedId, expires)

	return &encodedSignedToken, refreshToken, nil
}

func newRefreshToken(id string, expires time.Time) (*string, error) {
	token := Token{
		Id: id,
		Expires: expires.Add(time.Hour * 24),
		RefreshToken: true,
	}
	fmt.Println(token)

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
	decodedSignedToken := signedToken {}

	err := decodedSignedToken.decode(encodedSignedToken)
	if err != nil {
		return false, nil, err
	}

	verified := decodedSignedToken.verify()
	var decodedToken Token
	decodedToken.decode(decodedSignedToken.Data)

	expired := decodedToken.Expires.Compare(time.Now()) < 0

	return verified && !expired, &decodedToken, nil
}

func VerifyTokenId(encodedSignedToken string, id string) (bool, *Token, error) {
	verified, token, err := VerifyToken(encodedSignedToken)

	if !verified || err != nil {
		return false, nil, err
	}

	// Id's should be signed and encrypted, and therefore needed
	// to be encrypted and matched here before returning.
	return verified && token.Id == id, token, err
}