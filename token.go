package gobware

type Token struct {
	Secret string
	UserId string
	Expires int
	// Data: interface{} // field for arbitrary data stored with the token
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
