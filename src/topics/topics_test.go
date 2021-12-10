package topics

import (
	"fmt"
	"testing"
)

func TestMatch(t *testing.T) {
	testCases := []struct {
		savedTopic string
		givenTopic string
		expected   bool
	}{
		{"foo", "foo", true},
		{"foo", "bar", false},
		{"foo/bar", "foo", false},
		{"foo/bar", "foo/bar", true},
		{"foo/bar", "foo/baz", false},
		{"foo/+", "foo/bar", true},
		{"foo/+", "foo/baz", true},
		{"foo/#", "foo/bar", true},
		{"foo/#", "foo/baz", true},
		{"foo/#", "foo/baz/bar", true},
		{"foo/bar/baz", "foo/bar", false},
		{"foo/bar/baz", "foo/bar/baz", true},
		{"foo/+/baz", "foo/bar/baz", true},
		{"foo/+/baz", "foo/bar/bar", false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("saved: %s | given: %s | result: %t", tc.savedTopic, tc.givenTopic, tc.expected), func(t *testing.T) {
			if got := Match(tc.savedTopic, tc.givenTopic); got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
