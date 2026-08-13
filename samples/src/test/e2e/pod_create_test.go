// Excerpt of a Podman e2e spec, at the commit that failed.
//
// The failure reported against this spec is the "attribution" problem from
// the proposal: the spec that reports the failure is not the spec that caused
// it. The infra container name below is a fixed string, so an earlier spec
// that leaked a container with the same name breaks this innocent one.

package integration

import (
	. "github.com/containers/podman/v5/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Podman pod create", func() {

	It("podman pod create with --infra-command", func() {
		session := podmanTest.Podman([]string{
			"pod", "create", "--infra-command", "/pause1", "--name", "infra-cmd-pod",
		})
		session.WaitWithDefaultTimeout()
		Expect(session).Should(ExitCleanly())
	})

	It("podman pod create --infra-name", func() {
		// FIXME: a fixed name in a suite that runs across parallel Ginkgo
		// nodes and shares a container store. Any earlier spec that creates
		// "podman-test-infra" and does not clean it up in AfterEach makes
		// this spec fail with "the container name is already in use" — and
		// the failure gets attributed here rather than to the polluter.
		//
		// The fix is a unique name per spec:
		//
		//   infraName := fmt.Sprintf("podman-test-infra-%s", RandomString(8))
		infraName := "podman-test-infra"

		session := podmanTest.Podman([]string{
			"pod", "create", "--infra-name", infraName, "--name", "test-pod",
		})
		session.WaitWithDefaultTimeout()
		Expect(session).Should(ExitCleanly())

		check := podmanTest.Podman([]string{
			"pod", "inspect", "test-pod", "--format", "{{.InfraContainerID}}",
		})
		check.WaitWithDefaultTimeout()
		Expect(check).Should(ExitCleanly())
		Expect(check.OutputToString()).ToNot(BeEmpty())
	})
})
