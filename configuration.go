package gobware

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

const secretKey = "SECRET"
const saltKey = "SALT"
const pepperKey = "PEPPER"
const AccessTokenKey = "access"
const RefreshTokenKey = "refresh"

const TokenDuration = time.Hour
const tokenDurationMultiplier = 24

type configuration struct {
	AccessControlList *ACL
}

var config configuration = configuration{}

func SetACL(ACL *ACL) {
	config.AccessControlList = ACL
}

func GetACL() *ACL {
	return config.AccessControlList
}

func generateEnv() {
	file, err := os.Create("./.gobenv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	secret, err := GenerateSalt(32)
	if err != nil {
		panic(err)
	}
	salt, err := GenerateSalt(32)
	if err != nil {
		panic(err)
	}
	pepper, err := GenerateSalt(32)
	if err != nil {
		panic(err)
	}
	writer.WriteString(fmt.Sprintf("%s=%s\n", secretKey, base64.StdEncoding.EncodeToString(secret)))
	writer.WriteString(fmt.Sprintf("%s=%s\n", saltKey, base64.StdEncoding.EncodeToString(salt)))
	writer.WriteString(fmt.Sprintf("%s=%s", pepperKey, base64.StdEncoding.EncodeToString(pepper)))

	err = writer.Flush()
	if err != nil {
		panic(err)
	}
}

func init() {
	file, err := os.Open("./.gobenv")
	if err != nil {
		generateEnv()
		file, err = os.Open("./.gobenv")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				os.Setenv(key, value)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
