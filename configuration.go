package gobware

import (
	"encoding/base64"
	"os"
	"bufio"
	"fmt"
	"strings"
	"time"
)

const secretKey = "SECRET"
const saltKey = "SALT"
const pepperKey = "PEPPER"
const AccessTokenKey = "access"
const RefreshTokenKey = "refresh"
//const TokenDuration = time.Hour
const TokenDuration = time.Minute
const tokenDurationMultiplier = 24

type Configuration struct {
	AccessControlList ACL
}

var Config Configuration = Configuration{}

func SetACL(ACL ACL) {
	Config.AccessControlList = ACL
}

func generateEnv() {
	file, err := os.Create("./.gobenv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	secret, _ := GenerateSalt(256)
	salt, _ := GenerateSalt(256)
	pepper, _ := GenerateSalt(256)
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