package main

import (
	"fmt"
	"github.com/go-yaml/yaml"
	"io/ioutil"
	"flag"
	"github.com/pkg/errors"
	"strings"
	"os/exec"
)

func main() {
	fmt.Println("henlo bnois")
	var (
		c *ConfigData
		updates []TrackerIntegration
		err error
		passFilePath string
		baseFilePath string
		inputFilePath string
		outputFilePath string
	)

	passFilePath, baseFilePath, inputFilePath, outputFilePath, updates, err = parseArgs()

	if err != nil {
		fmt.Println(err)
		fmt.Println("Invalid args; usage : oauth_creds {base} {input} {output} --pass={ansible_password}")
		return
	}

	c, err = ReadConfig(baseFilePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	updates, err = ReadOptinions(inputFilePath, updates)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ApplyUpdates(c, updates, passFilePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	body, err := yaml.Marshal(c)
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile(outputFilePath, body, 0644)
	return
}

type MySQLConfig struct {
	DB    string `yaml:"db"`
	Login string `yaml:"login"`
	Pass  string `yaml:"pass"`
}

type Config struct {
	HTTPListen          string `yaml:"http/listen"`
	DefaultProjectLimit int    `yaml:"default_project_limit"`
	DefaultProject      bool   `yaml:"default_project"`
	Router              string `yaml:"router"`
	LogLevel            string `yaml:"log/level"`
	RSAPublicKey        string `yaml:"rsa_public_key"`
	AdminToken          string `yaml:"admin_token"`
}

type TrackerIntegration struct {
	URL         string `yaml:"url"`
	TrackerType string `yaml:"tracker_type"`
	ClientID    string `yaml:"client_id"`
	Secret      string `yaml:"secret"`
	RedirectURI string `yaml:"redirect_uri"`
}


type ConfigData struct {
	URL                 string               `yaml:"url"`
	Adapters            []string             `yaml:"adapters"`
	Config              Config               `yaml:"config"`
	MySQL               MySQLConfig          `yaml:"mysql"`
	TrackerIntegrations []TrackerIntegration `yaml:"tracker_integrations"`
}

func ReadConfig(filePath string) (*ConfigData, error){
	var c ConfigData
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal([]byte(yamlFile), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func ReadOptinions(filePath string, updates []TrackerIntegration) ([]TrackerIntegration, error){
	if filePath == "-" {
		return updates, nil
	}
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return updates, errors.Wrap(err, "cant open input file")
	}
	contents := strings.Split(string(file), "\n")
	for _, c := range contents {
		if c[0] == '#' {
			continue
		}
		ti, err := parseTrackerIntegrationString(strings.Split(c , " "))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Malformed update %v", c))
		}
		updates = append(updates, ti)
	}
	return updates, nil
}

func parseArgs () (pass, baseFilePath, inputFilePath, outputFilePath string, updates[]TrackerIntegration, err error) {
	flag.StringVar(&pass, "pass", "", "path to ansible password")
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		return "", "", "", "", nil, errors.New("Invalid Args")
	}
	var updateArgs []string
	if len(args) > 2 {
		updateArgs = args[3:]
	}
	updates, err = parseTrackerIntegrationStrings(updateArgs)
	if err != nil {
		return "", "", "", "", nil, err
	}
	return pass, args[0], args[1], args[2], updates, nil
}

func ApplyUpdates (c *ConfigData, updates []TrackerIntegration, pass string) error {
	indexMap := make(map[string]int)
	for index, value := range c.TrackerIntegrations {
		indexMap[value.TrackerType] = index
	}
	for _, update := range updates {
		index, ok := indexMap[update.TrackerType]
		if !ok {
			var integration TrackerIntegration
			if clientIdVault := ansibleEncryptString(pass, update.ClientID); clientIdVault != ""{
				integration.ClientID = clientIdVault
			} else {
				return errors.New(fmt.Sprintf("Failed to encrypt [clientID] : %v %v", update.TrackerType, update.ClientID))
			}
			if secretVault := ansibleEncryptString(pass, update.Secret); secretVault != ""{
				integration.Secret = secretVault
			} else {
				return errors.New(fmt.Sprintf("Failed to encrypt [Sectet] : %v %v", update.TrackerType, update.Secret))
			}
			integration.URL = "#fill manually!"
			integration.TrackerType = update.TrackerType
			integration.RedirectURI = c.TrackerIntegrations[0].RedirectURI
			c.TrackerIntegrations = append(c.TrackerIntegrations, integration)
		}
		integration := c.TrackerIntegrations[index]
		if clientIdVault := ansibleEncryptString(pass, update.ClientID); clientIdVault != "" && update.ClientID != "-" {
			integration.ClientID = clientIdVault
		} else {
			return errors.New(fmt.Sprintf("Failed to encrypt [clientID] : %v %v", update.TrackerType, update.ClientID))
		}
		if secretVault := ansibleEncryptString(pass, update.Secret); secretVault != "" && update.Secret != "-" {
			integration.Secret = secretVault
		} else {
			return errors.New(fmt.Sprintf("Failed to encrypt [Sectet] : %v %v", update.TrackerType, update.Secret))
		}
		c.TrackerIntegrations[index] = integration
	}
	return nil
}

func parseTrackerIntegrationString(args []string) (ti TrackerIntegration, err error) {
	if len(args) != 3 {
		return ti, errors.New(fmt.Sprintf("ignored tail %v", args))
	}
	return TrackerIntegration{
		TrackerType: strings.ToUpper(args[0]),
		ClientID: args[1],
		Secret: args[2],
	}, nil
}

func parseTrackerIntegrationStrings(args []string) ([]TrackerIntegration, error) {
	var tis []TrackerIntegration
	for i:=0; i < len(args); i+=3 {
		if len(args) -i < 3 {
			return nil, errors.New(fmt.Sprintf("Cannot parse update %v", args[i:]))
		}
		ti, err := parseTrackerIntegrationString(args[i:i+3])
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Malformed update %v", args[i:i+3]))
		} else {
			tis = append(tis, ti)
		}
	}
	return tis, nil
}

func ansibleEncryptString(passFilePath string, data string) string {
	cmd := fmt.Sprintf("ansible-vault encrypt_string \"%v\" --vault-id %v", data, passFilePath)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(out)
}