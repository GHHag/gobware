package gobware

import (
	"net/http"
	"encoding/base64"
	"os"
	"bufio"
	"fmt"
	"strings"
)

const SecretKey = "SECRET"
const SaltKey = "SALT"

// Define constand Configuration struct?
/*const Config Configuration {
	roleKey: "role",
}*/

func generateEnv() {
	file, err := os.Create("./.gobenv")
	if err != nil {
		// Return error instead of panic?
		panic(err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	secret, _ := GenerateSalt(128)
	salt, _ := GenerateSalt(128)
	writer.WriteString(fmt.Sprintf("%s=%s\n", SecretKey, base64.StdEncoding.EncodeToString(secret)))
	writer.WriteString(fmt.Sprintf("%s=%s", SaltKey, base64.StdEncoding.EncodeToString(salt)))

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

	if err := scanner.Err(); err != nil {
        panic(err)
    }
}

/*

Use Template package to generate/define Configuration/settings?

Define a Template for Token and use as a generic way of evaluating
the token in a ChainLink?

*/

type ChainLink func(*http.Request) bool

type Configuration struct {
	chain []ChainLink
	accessControlList *ACL
	roleKey string
	tokenKey string
}

func NewConfiguration(ACL *ACL, roleKey string) *Configuration {
	return &Configuration{
		chain: []ChainLink{},
		accessControlList: ACL,
		roleKey: roleKey,
		tokenKey: CookieBaker.tokenKey,
	}
}

func(config *Configuration) AddChainLink(chainLink ChainLink) {
	config.chain = append(config.chain, chainLink)
}

// Run ChainLink functions concurrent?
func(config *Configuration) RunChain(r *http.Request) bool {
	for _, chainLink := range config.chain {
		pass := chainLink(r)
	
		if !pass {
			return false
		}
	}

	return true
}