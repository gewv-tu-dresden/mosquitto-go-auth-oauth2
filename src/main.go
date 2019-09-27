package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/iegomez/mosquitto-go-auth/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type void struct{}

type userState struct {
	username          string
	accessToken       string
	refreshToken      string
	expiry            time.Time
	superuser         bool
	readTopics        []string
	writeTopics       []string
	lastUserInfoUpate time.Time
}

// type Topics struct {
// 	read  []string `json:"read"`
// 	write []string `json:"write"`
// }

type UserInfo struct {
	Topics struct {
		Read  []string `json:"read"`
		Write []string `json:"write"`
	} `json:"topics"`
	Superuser bool `json:"superuser"`
}

var config oauth2.Config
var userInfoURL string
var userCache map[string]userState

func getUserInfo(token string) (*UserInfo, error) {
	info := UserInfo{}

	client := &http.Client{}

	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(&info)

	log.Infoln("Got userinfo from auth backend:")
	log.Info(string(out))

	return &info, nil
}

func isTopicInList(topicList []string, searchedTopic string) bool {
	for _, topicFromList := range topicList {
		if common.TopicsMatch(topicFromList, searchedTopic) {
			return true
		}
	}
	return false
}

func checkAccessToTopic(topic string, acc int, info *UserInfo) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := isTopicInList(info.Topics.Read, topic)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := isTopicInList(info.Topics.Write, topic)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := isTopicInList(info.Topics.Read, topic) && isTopicInList(info.Topics.Write, topic)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}

func Init(authOpts map[string]string, logLevel log.Level) error {
	// Initialize your plugin with the necessary options
	log.SetLevel(logLevel)

	log.Infof("Plugin initialized!")
	clientID, ok := authOpts["oauth_client_id"]
	if !ok {
		log.Panic("Got no clientId for oauth plugin.")
	}
	clientSecret, ok := authOpts["oauth_client_secret"]
	if !ok {
		log.Panic("Got no client secret for oauth plugin.")
	}
	tokenURL, ok := authOpts["oauth_token_url"]
	if !ok {
		log.Panic("Got no token endpoint for oauth plugin.")
	}
	userInfoURL, ok = authOpts["oauth_userinfo_url"]
	if !ok {
		log.Panic("Got no userState endpoint for oauth plugin.")
	}

	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"all"},
		RedirectURL:  "",
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenURL,
			AuthURL:  "",
		},
	}

	userCache = make(map[string]userState)

	return nil
}

func GetUser(username, password string) bool {
	// Get token for the credentials and verify the user
	log.Infof("Checking user with oauth plugin.")
	token, err := config.PasswordCredentialsToken(context.Background(), username, password)

	if err != nil {
		log.Println(err)
		return false
	}

	userCache[username] = userState{
		username:     username,
		accessToken:  token.AccessToken,
		refreshToken: token.RefreshToken,
		expiry:       token.Expiry,
		superuser:    false,
	}

	return true
}

func GetSuperuser(username string) bool {
	// Function that checks if the user has admin privilies
	log.Infof("Checking if user %s is a superuser.", username)

	cache, ok := userCache[username]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return false
	}

	info, err := getUserInfo(cache.accessToken)

	if err != nil {
		log.Errorf("Failed to receive UserInfo for user %s: %s", username, err)
		return false
	}

	log.Debugf("Check for superuser was %t", info.Superuser)
	return info.Superuser
}

func CheckAcl(username, topic, clientid string, acc int) bool {
	// Function that checks if the user has the right to access a address
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache, ok := userCache[username]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return false
	}

	info, err := getUserInfo(cache.accessToken)

	if err != nil {
		log.Errorf("Failed to receive UserInfo for user %s: %s", username, err)
		return false
	}

	res := checkAccessToTopic(topic, acc, info)
	log.Debugf("ACL check was %t", res)
	return res
}

func GetName() string {
	return "OAuth Plugin"
}

func Halt() {
	// Do whatever cleanup is needed.
}
