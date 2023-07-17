package gobware

import(
)

type TokenAlgorithm interface {
	Algorithm(token *Token)
	Encrypt(token *Token)
	Decrypt(token *Token)
}

type KekwAlgorithm struct {
	
}

type BautaAlgorithm struct {

}

func (algo KekwAlgorithm) Algorithm(token *Token, encrypt bool)(*Token){
	if encrypt {
		token.Encoded = true
		return token
	} else{
		token.Encoded = false
		return token
	}
}

func (algo KekwAlgorithm) Encrypt(token *Token)(*Token){
	algo.Algorithm(token, true)

	return token
}

func (algo KekwAlgorithm) Decrypt(token *Token)(*Token){
	algo.Algorithm(token, false)

	return token
}