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

type Configuration struct {
	acl *acl
}

func (config *Configuration) SetACL(acl *acl) {
	config.acl = acl
}

func (config *Configuration) AddACLRule(role string, route string, httpMethods []string) {
	if config.acl != nil {
		config.acl.addACLRule(role, route, httpMethods)
	}
}

func (config *Configuration) CheckAccess(userData map[string]string, route string, httpMethod string) bool {
	if config.acl != nil {
		return config.acl.checkAccess(userData, route, httpMethod)
	} else {
		return false
	}
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
