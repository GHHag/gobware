package gobware

import(
)

type TokenAlgorithm interface {
	Algorithm(*Token, bool)(*Token)
	Encrypt(*Token)(*Token)
	Decrypt(*Token)(*Token)
}

type KekwAlgorithm struct {
	//Algorithm func(*Token)(*Token)
	//Encrypt func(*Token)
	//Decrypt func(*Token)
}

type BautaAlgorithm struct {
	Algorithm func(*Token)
	Encrypt func(*Token)
	Decrypt func(*Token)
}

func (algo KekwAlgorithm) Algorithm(token *Token, encrypt bool)(*Token){
	token.Encoded = true

	return token
}

func (algo KekwAlgorithm) Encrypt(token *Token)(*Token){
	algo.Algorithm(token, true)

	return token
}

func (algo KekwAlgorithm) Decrypt(token *Token)(*Token){
	algo.Algorithm(token, false)

	return token
}