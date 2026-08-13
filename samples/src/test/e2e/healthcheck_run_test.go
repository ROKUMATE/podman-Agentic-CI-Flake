// Excerpt of a Podman e2e spec, at the commit that failed.
//
// This file exists so the agent's get_test_source tool has something real to
// read. The failing spec below is the case the proposal calls out by name: a
// test that waits a fixed amount of time instead of waiting for the condition.
// The log alone cannot tell you that; the source can.

package integration

import (
	"fmt"
	"time"

	. "github.com/containers/podman/v5/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Podman healthcheck run", func() {

	It("podman disable healthcheck with --no-healthcheck on valid container", func() {
		session := podmanTest.Podman([]string{"run", "-dt", "--no-healthcheck", "--name", "hc", HEALTHCHECK_IMAGE})
		session.WaitWithDefaultTimeout()
		Expect(session).Should(ExitCleanly())

		hc := podmanTest.Podman([]string{"healthcheck", "run", "hc"})
		hc.WaitWithDefaultTimeout()
		Expect(hc).Should(ExitWithError(125, "has no defined healthcheck"))
	})

	It("podman healthcheck run that succeeds", func() {
		name := fmt.Sprintf("hc-%s", RandomString(12))
		session := podmanTest.Podman([]string{
			"run", "-dt", "--name", name,
			"--health-cmd", "CMD-SHELL /healthcheck.sh",
			"--health-interval", "1s",
			"--health-retries", "3",
			HEALTHCHECK_IMAGE,
		})
		session.WaitWithDefaultTimeout()
		Expect(session).Should(ExitCleanly())

		// FIXME: this is the bug. The healthcheck interval is 1s and the
		// retry count is 3, so convergence can take up to ~3s plus process
		// startup — but this waits a flat 2s and then asserts. On a loaded
		// runner the container is still "starting" when the assertion runs,
		// and the spec fails through no fault of the product.
		//
		// The fix is to wait on the condition, not on the clock:
		//
		//   Eventually(func() string {
		//       return healthStatus(name)
		//   }, "30s", "1s").Should(Equal("healthy"))
		time.Sleep(2 * time.Second)

		inspect := podmanTest.Podman([]string{
			"container", "inspect", "--format", "{{.State.Health.Status}}", name,
		})
		inspect.WaitWithDefaultTimeout()
		Expect(inspect).Should(ExitCleanly())
		Expect(inspect.OutputToString()).To(Equal("healthy"))
	})

	It("podman healthcheck on non-running container", func() {
		session := podmanTest.Podman([]string{"create", "--name", "hc-stopped", HEALTHCHECK_IMAGE})
		session.WaitWithDefaultTimeout()
		Expect(session).Should(ExitCleanly())

		hc := podmanTest.Podman([]string{"healthcheck", "run", "hc-stopped"})
		hc.WaitWithDefaultTimeout()
		Expect(hc).Should(ExitWithError(125, "is not running"))
	})
})
