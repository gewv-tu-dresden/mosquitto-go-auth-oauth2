package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/sirupsen/logrus"
)

func setupMockOAuthServer() (*httptest.Server, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		// return info to the user in a json
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"superuser\":true,\"topics\":{\"read\":[\"/test/topic/read/#\",\"/test/topic/writeread/1\"],\"write\":[\"/test/topic/write/+/db\",\"/test/topic/writeread/1\"]}}"))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Should return acccess token back to the user
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=mock_token&scope=user&token_type=bearer&refresh_token=mock_refresh_token"))
	})

	server := httptest.NewServer(mux)

	return server, func() {
		server.Close()
		log.Infof("Close Testserver")
	}
}

func createOAuthServer(t *testing.T) (*httptest.Server, func()) {
	// start muck server
	server, closeServer := setupMockOAuthServer()
	log.Infof("Start Testserver on location %s", server.URL)

	var authOpts map[string]string
	authOpts = make(map[string]string)

	authOpts["oauth_client_id"] = "clientId"
	authOpts["oauth_client_secret"] = "clientSecret"
	authOpts["oauth_token_url"] = server.URL + "/token"
	authOpts["oauth_userinfo_url"] = server.URL + "/userinfo"

	err := Init(authOpts, log.DebugLevel)
	if err != nil {
		t.Errorf("Failed to init plugin: %s", err)
	}
	return server, closeServer
}

func TestInit(t *testing.T) {
	_, closeServer := createOAuthServer(t)
	defer closeServer()
}

func TestGetUserPositiv(t *testing.T) {
	// first init plugin to create oauth server and client
	_, closeServer := createOAuthServer(t)
	defer closeServer()

	allowed := GetUser("test", "test")
	if !allowed {
		t.Errorf("Positive GetUser() Response was negative!")
	}
}

func TestGetSuperuserPositiv(t *testing.T) {
	// first init plugin to create oauth server and client
	_, closeServer := createOAuthServer(t)
	defer closeServer()

	GetUser("test", "test")
	allowed := GetSuperuser("test")
	if !allowed {
		t.Errorf("Positive GetSuperuser() Response was negative!")
	}
}

func TestCheckAclPositiv(t *testing.T) {
	// first init plugin to create oauth server and client
	_, closeServer := createOAuthServer(t)
	defer closeServer()

	GetUser("test", "test")
	// test read access
	allowed := CheckAcl("test", "/test/topic/read/sensor", "foo", 1)
	if !allowed {
		t.Errorf("Positive CheckAcl() Response was negative!")
	}

	// test write access
	allowed = CheckAcl("test", "/test/topic/write/influx/db", "foo", 2)
	if !allowed {
		t.Errorf("Positive CheckAcl() Response was negative!")
	}

	// test write access
	allowed = CheckAcl("test", "/test/topic/writeread/1", "foo", 3)
	if !allowed {
		t.Errorf("Positive CheckAcl() Response was negative!")
	}
}
