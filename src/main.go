package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
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
	createdAt         time.Time
	updatedAt         time.Time
	usernameIsToken   bool
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

	log.Infoln("Got userinfo from auth backend")
	log.Debug(string(out))

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

func checkAccessToTopic(topic string, acc int, cache *userState) bool {
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
	log.Infof("Cache Expiary: %s", cacheDuration)
	log.Infof("Last Update: %s", cache.updatedAt)
	log.Infof("Difference to now: %s", time.Now().Sub(cache.updatedAt))

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

	userCache[username] = userState{
		username:     username,
		accessToken:  token.AccessToken,
		refreshToken: token.RefreshToken,
		expiry:       token.Expiry,
		superuser:    false,
		createdAt:    time.Now(),
		updatedAt:    time.Unix(0, 0),
	}

	return true
}

func createUserWithToken(token string) bool {
	info, err := getUserInfo(token)

	if err != nil {
		log.Println(err)
		return false
	}

	userCache[token] = userState{
		username:        token,
		accessToken:     token,
		usernameIsToken: true,
		refreshToken:    "",
		expiry:          time.Unix(0, 0),
		superuser:       info.MQTT.Superuser,
		createdAt:       time.Now(),
		updatedAt:       time.Now(),
		readTopics:      info.MQTT.Topics.Read,
		writeTopics:     info.MQTT.Topics.Write,
	}

	return true
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

func GetUser(username, password string) bool {
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
		info, err := getUserInfo(cache.accessToken)

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

func CheckAcl(username, topic, clientid string, acc int) bool {
	// Function that checks if the user has the right to access a address
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache, ok := userCache[username]
	if !ok {
		log.Warnf("Have no entry in user cache for user %s", username)
		return false
	}

	if !cacheIsValid(&cache) {
		info, err := getUserInfo(cache.accessToken)

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
	return "OAuth Plugin"
}

func Halt() {
	// Do whatever cleanup is needed.
}
