package gobware

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const secretKey = "SECRET"

var (
	secret                  string
	salt                    string
	pepper                  string
	accessTokenKey          string
	refreshTokenKey         string
	tokenDuration           time.Duration
	tokenDurationMultiplier time.Duration
)

func GetAccessTokenKey() string {
	return accessTokenKey
}

func GetRefreshTokenKey() string {
	return refreshTokenKey
}

func GetTokenDuration() time.Duration {
	return tokenDuration
}

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

func generateSecret() {
	file, err := os.Create("./.gobenv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	secret, err := GenerateRandomByteArray(32)
	if err != nil {
		panic(err)
	}
	writer.WriteString(fmt.Sprintf("%s=%s\n", secretKey, base64.StdEncoding.EncodeToString(secret)))

	err = writer.Flush()
	if err != nil {
		panic(err)
	}
}

func init() {
	accessTokenKeyPtr := flag.String("access-token-key", "access", "access token cookie key")
	refreshTokenKeyPtr := flag.String("refresh-token-key", "refresh", "refresh token cookie key")
	tokenDurationPtr := flag.String("token-duration", "hour", "access token duration, accepted values: minute, hour, day")
	tokenDurationMultiplierPtr := flag.Int("token-duration-multiplier", 24, "access token duration multiplier, determines the duration of refresh tokens")
	flag.Parse()

	accessTokenKey = *accessTokenKeyPtr
	refreshTokenKey = *refreshTokenKeyPtr
	switch *tokenDurationPtr {
	case "minute":
		tokenDuration = time.Minute
	case "hour":
		tokenDuration = time.Hour
	case "day":
		tokenDuration = time.Hour * 24
	default:
		tokenDuration = time.Hour
	}
	tokenDurationMultiplier = time.Duration(*tokenDurationMultiplierPtr)

	file, err := os.Open("./.gobenv")
	if err != nil {
		generateSecret()
		file, err = os.Open("./.gobenv")
		if err != nil {
			panic(err)
		}
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

	secret = os.Getenv(secretKey)

	saltValue, err := GenerateRandomByteArray(32)
	if err != nil {
		panic(err)
	}
	salt = base64.StdEncoding.EncodeToString(saltValue)

	pepperValue, err := GenerateRandomByteArray(32)
	if err != nil {
		panic(err)
	}
	pepper = base64.StdEncoding.EncodeToString(pepperValue)

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
