package server

import (
	"testing"

	"github.com/sirupsen/logrus"

	"k8s.io/test-infra/prow/github"
	"k8s.io/test-infra/prow/github/fakegithub"
	//"k8s.io/test-infra/prow/labels"
)

func TestHandle(t *testing.T) {

	var tests = []struct {
		name          string
		userName      string
		body          string
		hasLabel      bool
		shouldLabel   bool
		shouldUnlabel bool
	}{
		{
			name:          "test random comment",
			userName:      "random-user",
			body:          "random comment",
			hasLabel:      false,
			shouldLabel:   false,
			shouldUnlabel: false,
		},
	}

	for _, tc := range tests {
		fc := &fakegithub.FakeClient{
			IssueComments: make(map[int][]github.IssueComment),
		}

		s := &Server{
			GHC: fc,
		}

		ic := github.IssueCommentEvent{
			Action: github.IssueCommentActionCreated,
			Repo: github.Repo{
				Owner: github.User{
					Login: "someorg",
				},
				Name: "somerepo",
			},
			Issue: github.Issue{
				Number: 1,
			},
			Comment: github.IssueComment{
				User: github.User{
					Login: tc.userName,
				},
				Body: tc.body,
			},
		}
		if err := s.handleIssueComment(logrus.WithField("plugin", pluginName), ic); err != nil {
			t.Errorf("For case %s, didn't expect error from release-blocker: %v", tc.name, err)
			continue
		}

	}
}
