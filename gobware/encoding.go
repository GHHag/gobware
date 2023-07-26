package gobware

type IEncoder interface {
	encode(string)
}

type Encoder struct {

}

func(encoder Encoder) encode(value string){

}

type PasswordEncoder struct {

}

func(encoder PasswordEncoder) encode(value string){

}
