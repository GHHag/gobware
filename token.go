package gobware

import (
	"errors"
	"encoding/base64"
	"encoding/json"
	"crypto/hmac"
	"crypto/sha256"
	"time"
	"net/http"
	"os"
)

type CreateToken func(time.Time, map[string]string) (string, error)
type RequestToken func(*http.Request, time.Time, CreateToken) (string, error)
type CreateTokenPair func(time.Time, map[string]string) (string, string, error)
type RequestTokenPair func(*http.Request, time.Time, CreateTokenPair) (string, string, error)

type Token struct {
	Id string `json:"id"`
	Expires time.Time
	Data map[string]string `json:"data"`
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
	mac := hmac.New(sha256.New, []byte(os.Getenv(secretKey) + os.Getenv(saltKey)))
	mac.Write([]byte(signedToken.Data))
	signedToken.Signature = []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func(signedToken *signedToken) verify() bool {
	mac := hmac.New(sha256.New, []byte(os.Getenv(secretKey) + os.Getenv(saltKey)))
	mac.Write(signedToken.Data)

	expected := []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	return hmac.Equal(signedToken.Signature, expected)
}

func NewToken(expires time.Time, data map[string] string) (string, error) {
	id, _ := GenerateId(256)

	token := Token{
		Id: base64.StdEncoding.EncodeToString(id),
		Expires: expires,
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

func NewTokenPair(expires time.Time, data map[string]string) (string, string, error) {
	id, _ := GenerateId(256)
	idHash := HashData(sha256.Sum256, id, []byte(os.Getenv(secretKey)), []byte(os.Getenv(pepperKey)))

	token := Token{
		Id: base64.StdEncoding.EncodeToString(id),
		Expires: expires,
		Data: data,
	}

	var err error

	signedToken := signedToken{}
	signedToken.Data, err = token.encode()
	if err != nil {
		return "", "", err
	}
	signedToken.sign()

	encodedSignedToken, err := signedToken.encode()
	if err != nil {
		return "", "", err
	}

	refreshToken, err := newRefreshToken(base64.StdEncoding.EncodeToString(idHash), expires)
	if err != nil {
		return "", "", err
	}

	return encodedSignedToken, refreshToken, nil
}

func newRefreshToken(id string, expires time.Time) (string, error) {
	token := Token{
		Id: id,
		Expires: expires.Add(TokenDuration * tokenDurationMultiplier),
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
		return false, nil, err
	}

	verified := decodedSignedToken.verify()
	var decodedToken Token
	decodedToken.decode(decodedSignedToken.Data)

	expired := decodedToken.Expires.Compare(time.Now()) < 0

	return verified && !expired, &decodedToken, nil
}

/*func VerifyTokenId(encodedSignedToken string, id string) (bool, *Token, error) {
	verified, token, err := VerifyToken(encodedSignedToken)

	if !verified || err != nil {
		return false, nil, err
	}

	// Id's should be signed and encrypted, and therefore needed
	// to be encrypted and matched here before returning.
	return verified && token.Id == id, token, err
}*/

func ExchangeTokens(encodedSignedAccessToken string, encodedSignedRefreshToken string, expires time.Time) (string, string, error) {
	decodedSignedAccessToken := signedToken{}
	decodedSignedRefreshToken := signedToken{}
	aErr := decodedSignedAccessToken.decode(encodedSignedAccessToken)
	rErr := decodedSignedRefreshToken.decode(encodedSignedRefreshToken)
	if aErr != nil || rErr != nil {
		return "", "", errors.New("Failed to decode tokens.")
	}

	aVerified := decodedSignedAccessToken.verify()
	rVerified := decodedSignedRefreshToken.verify()
	var decodedAccessToken Token
	var decodedRefreshToken Token
	decodedAccessToken.decode(decodedSignedAccessToken.Data)
	decodedRefreshToken.decode(decodedSignedRefreshToken.Data)
	if !aVerified || !rVerified {
		return "", "", errors.New("Failed to verify tokens.")
	}

	expired := decodedRefreshToken.Expires.Compare(time.Now()) < 0
	if expired {
		return "", "", errors.New("Token expired.")
	}

	decodedAccessTokenId, _ := base64.StdEncoding.DecodeString(decodedAccessToken.Id)
	decodedRefreshTokenId, _ := base64.StdEncoding.DecodeString(decodedRefreshToken.Id)
	tokenPairVerified := VerifyData(
		sha256.Sum256, decodedAccessTokenId,
		[]byte(os.Getenv(secretKey)), []byte(os.Getenv(pepperKey)), 
		decodedRefreshTokenId,
	)
	if !tokenPairVerified {
		return "", "", errors.New("Failed to verify tokens.")
	}

	accessToken, refreshToken, err := NewTokenPair(expires, decodedAccessToken.Data)
	return accessToken, refreshToken, err
}

func AttemptTokenExchange(accessToken string, refreshToken string, expires time.Time) (string, string, error) {
	validated, _, err := VerifyToken(refreshToken)
	if validated && err == nil {
		accessToken, refreshToken, err := ExchangeTokens(accessToken, refreshToken, expires)

		return accessToken, refreshToken, err
	} else {
		return "", "", err
	}
}

func BakeCookie(name string, value string, expires time.Time) *http.Cookie {
	return &http.Cookie {
		Name: name,
		Value: value,
		Expires: expires.Add(TokenDuration * tokenDurationMultiplier),
		HttpOnly: true,
		Secure: true,
		SameSite: http.SameSiteStrictMode,
	}
}
