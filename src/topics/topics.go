package topics

import "strings"

// original made by iegomez
// https://github.com/iegomez/mosquitto-go-auth/blob/master/backends/topics/topics.go

// Match tells if givenTopic matches savedTopic's pattern.
func Match(savedTopic, givenTopic string) bool {
	return givenTopic == savedTopic || match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
}

func match(route []string, topic []string) bool {
	switch {
	case len(route) == 0:
		return len(topic) == 0
	case len(topic) == 0:
		return route[0] == "#"
	case route[0] == "#":
		return true
	case route[0] == "+", route[0] == topic[0]:
		return match(route[1:], topic[1:])
	}

	return false
}
