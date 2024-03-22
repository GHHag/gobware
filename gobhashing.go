package gobware

import (
	"crypto/hmac"
	"crypto/rand"
)

/*

Hashing:
1. Generate and store salt
2. Combine data to hash with the salt and pepper
3. Compute SHA256 (or other secure algorithm) of the combined data, salt and pepper
4. Store data

Verifying:
1. Unhashed data is provided
2. Stored hash and salt is retrieved
3. Compute SHA256 (or other secure algorithm) of the combined data, salt and pepper
4. Compare the newly generated hash with the stored hash
5. If they match the provided data is correct

*/

type Algorithm func([]byte) [32]byte

func GenerateRandomByteArray(length int) ([]byte, error) {
	byteArray := make([]byte, length)
	_, err := rand.Read(byteArray)
	return byteArray, err
}

func HashData(algorithm Algorithm, data []byte, salt []byte, pepper []byte) []byte {
	saltAndPepper := append(salt, pepper...)
	hash := algorithm(append(data, saltAndPepper...))
	return hash[:]
}

func VerifyData(algorithm Algorithm, data []byte, salt []byte, pepper []byte, hash []byte) bool {
	hashedData := HashData(algorithm, data, salt, pepper)
	return hmac.Equal(hash, hashedData)
}
