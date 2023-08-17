package gobware

import (
	"encoding/base64"
	"os"
	"bufio"
	"fmt"
	"strings"
	"time"
)

// Define constant Configuration struct?
// Allow package user to inject configuration struct?

const SecretKey = "SECRET"
const SaltKey = "SALT"
const PepperKey = "PEPPER"
const accessTokenKey = "access"
const refreshTokenKey = "refresh"
//const tokenDuration = time.Hour
const tokenDuration = time.Minute

type Configuration struct {
	accessControlList *ACL
	RoleKey string
	AccessTokenKey string
	RefreshTokenKey string
	TokenDuration time.Duration
}

var Config Configuration = Configuration {
	AccessTokenKey: accessTokenKey,
	RefreshTokenKey: refreshTokenKey,
	TokenDuration: tokenDuration,
}

func SetACL(ACL *ACL) {
	Config.accessControlList = ACL
}

func generateEnv() {
	file, err := os.Create("./.gobenv")
	if err != nil {
		// Return error instead of panic?
		panic(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	secret, _ := GenerateSalt(256)
	salt, _ := GenerateSalt(256)
	pepper, _ := GenerateSalt(256)
	writer.WriteString(fmt.Sprintf("%s=%s\n", SecretKey, base64.StdEncoding.EncodeToString(secret)))
	writer.WriteString(fmt.Sprintf("%s=%s", SaltKey, base64.StdEncoding.EncodeToString(salt)))
	writer.WriteString(fmt.Sprintf("%s=%s", PepperKey, base64.StdEncoding.EncodeToString(pepper)))

	err = writer.Flush()
	if err != nil {
		// Return error instead of panic?
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

	// If "SECRET" or "SALT" is not set as env vars then generate them

	if err := scanner.Err(); err != nil {
        panic(err)
    }
}

/*

Use Template package to generate/define Configuration/settings?

*/

/*type Configuration struct {
	accessControlList *ACL
	//roleKey string
	//accessTokenKey string
	//refreshTokenKey string
	//tokenDuration time.Duration
}*/

//func NewConfiguration(ACL *ACL, roleKey string, tokenDuration time.Duration) *Configuration {
/*func NewConfiguration(ACL *ACL) *Configuration {
	return &Configuration{
		accessControlList: ACL,
		//roleKey: roleKey,
		//accessTokenKey: CookieBaker.accessTokenKey,
		//refreshTokenKey: CookieBaker.refreshTokenKey,
		//tokenDuration: tokenDuration,
	}
}*/