package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	// "golang.org/x/oauth2"
)

type void struct{}

type userState struct {
	username          string
	superuser         bool
	readTopics        []string
	writeTopics       []string
	lastUserInfoUpate time.Time
	createdAt         time.Time
	updatedAt         time.Time
	usernameIsToken   bool
	client            *http.Client
	token             *oauth2.Token
}

// type Topics struct {
// 	read  []string `json:"read"`
// 	write []string `json:"write"`
// }

type UserInfo struct {
	MQTT struct {
		Topics struct {
			Read  []string `json:"read"`
			Write []string `json:"write"`
		} `json:"topics"`
		Superuser bool `json:"superuser"`
	} `json:"mqtt"`
}

var config oauth2.Config
var userInfoURL string
var userCache map[string]userState
var cacheDuration time.Duration
var version string

func getUserInfo(client *http.Client) (*UserInfo, error) {
	info := UserInfo{}

	req, _ := http.NewRequest("GET", userInfoURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(&info)

	log.Infoln("Got userinfo from auth backend")
	log.Debug(string(out))

	return &info, nil
}

func isTopicInList(topicList []string, searchedTopic string) bool {
	for _, topicFromList := range topicList {
		if topicsMatch(topicFromList, searchedTopic) {
			return true
		}
	}
	return false
}

func topicsMatch(savedTopic, givenTopic string) bool {
	return givenTopic == savedTopic || match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
}

func match(route []string, topic []string) bool {
	if len(route) == 0 {
		if len(topic) == 0 {
			return true
		}
		return false
	}

	if len(topic) == 0 {
		if route[0] == "#" {
			return true
		}
		return false
	}

	if route[0] == "#" {
		return true
	}

	if (route[0] == "+") || (route[0] == topic[0]) {
		return match(route[1:], topic[1:])
	}

	return false
}

func checkAccessToTopic(topic string, acc int32, cache *userState) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := isTopicInList(cache.readTopics, topic)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := isTopicInList(cache.writeTopics, topic)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := isTopicInList(cache.readTopics, topic) && isTopicInList(cache.writeTopics, topic)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}

func cacheIsValid(cache *userState) bool {
	log.Debugf("Cache Expiary: %s", cacheDuration)
	log.Debugf("Last Update: %s", cache.updatedAt)
	log.Debugf("Difference to now: %s", time.Now().Sub(cache.updatedAt))

	// function tests if the cache of the user is still valid
	if cacheDuration == 0 {
		return false
	}

	if (time.Now().Sub(cache.updatedAt)) < cacheDuration {
		return true
	}
	return false
}

func createUserWithCredentials(username, password string) bool {
	token, err := config.PasswordCredentialsToken(context.Background(), username, password)

	if err != nil {
		log.Println(err)
		return false
	}

	oauthClient := config.Client(context.Background(), token)

	userCache[username] = userState{
		username:  username,
		superuser: false,
		createdAt: time.Now(),
		updatedAt: time.Unix(0, 0),
		client:    oauthClient,
		token:     token,
	}

	return true
}

func createUserWithToken(accessToken string) bool {
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
	client := config.Client(context.Background(), token)
	info, err := getUserInfo(client)

	if err != nil {
		log.Println(err)
		return false
	}

	userCache[accessToken] = userState{
		username:        accessToken,
		usernameIsToken: true,
		superuser:       info.MQTT.Superuser,
		createdAt:       time.Now(),
		updatedAt:       time.Now(),
		readTopics:      info.MQTT.Topics.Read,
		writeTopics:     info.MQTT.Topics.Write,
		client:          client,
		token:           token,
	}

	return true
}

func Init(authOpts map[string]string, logLevel log.Level) error {
	// Initialize your plugin with the necessary options
	log.SetLevel(logLevel)

	// Version of the plugin
	version = "v1.1"

	log.Infof("OAuth Plugin " + version + " initialized!")
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
	cacheDurationSeconds, ok := authOpts["oauth_cache_duration"]
	if ok {
		durationInt, err := strconv.Atoi(cacheDurationSeconds)
		if err != nil {
			log.Panic("Got no valid cache duration for oauth plugin.")
		}

		cacheDuration = time.Duration(durationInt) * time.Second
	} else {
		cacheDuration = 0
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

func GetUser(username, password, clientid string) bool {
	// Get token for the credentials and verify the user
	log.Infof("Checking user with oauth plugin.")
	if password == "" {
		// If no password was delivered the username is interpreted as a token
		return createUserWithToken(username)
	}

	return createUserWithCredentials(username, password)
}

func GetSuperuser(username string) bool {
	// Function that checks if the user has admin privilies
	log.Infof("Checking if user %s is a superuser.", username)

	cache, ok := userCache[username]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return false
	}

	if !cacheIsValid(&cache) {
		if !cache.token.Valid() {
			log.Warningf("Token for user %s invalid. Try to refresh.", username)
		}

		info, err := getUserInfo(cache.client)

		if err != nil {
			log.Errorf("Failed to receive UserInfo for user %s: %s", username, err)
			return false
		}

		cache.superuser = info.MQTT.Superuser
		cache.readTopics = info.MQTT.Topics.Read
		cache.writeTopics = info.MQTT.Topics.Write
		cache.updatedAt = time.Now()
	} else {
		log.Infof("Get userinfo from cache")
	}

	log.Debugf("Check for superuser was %t", cache.superuser)
	userCache[username] = cache
	return cache.superuser
}

func CheckAcl(username, topic, clientid string, acc int32) bool {
	// Function that checks if the user has the right to access a address
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache, ok := userCache[username]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return false
	}

	if !cacheIsValid(&cache) {
		info, err := getUserInfo(cache.client)

		if err != nil {
			log.Errorf("Failed to receive UserInfo for user %s: %s", username, err)
			return false
		}

		cache.superuser = info.MQTT.Superuser
		cache.readTopics = info.MQTT.Topics.Read
		cache.writeTopics = info.MQTT.Topics.Write
		cache.updatedAt = time.Now()
	}

	res := checkAccessToTopic(topic, acc, &cache)
	log.Debugf("ACL check was %t", res)
	return res
}

func GetName() string {
	return "OAuth Plugin " + version
}

func GetScopes() []string {
	return config.Scopes
}

func Halt() {
	// Do whatever cleanup is needed.
}
