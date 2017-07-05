package PLUS_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestPlus(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Plus Suite")
}
