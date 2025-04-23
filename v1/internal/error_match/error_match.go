package error_match

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

type Matcher func(t testing.TB, err error) bool

func newMatcherPtr(matcher Matcher) *Matcher {
	return ptr.To(matcher)
}

func NoError() *Matcher {
	return newMatcherPtr(func(t testing.TB, err error) bool {
		return assert.NoError(t, err)
	})
}

func ErrorContains(contains string) *Matcher {
	return newMatcherPtr(func(t testing.TB, err error) bool {
		return assert.ErrorContains(t, err, contains)
	})
}
