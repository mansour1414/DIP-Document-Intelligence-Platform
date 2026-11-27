/**
 * A test entrypoint for the supervisor process, with a fixture cgroup hierarchy (R7D.1).
 *
 * ## Why this file exists, and why it is not in `workers/`
 *
 * The end-to-end harness must run the *real* supervisor as a subprocess: real sockets, real
 * journal, real lifecycle, real daemon calls. What it cannot obtain in a nested container is a
 * writable cgroup2 hierarchy, so the kernel facts that describe a container's cgroup come from a
 * fixture tree instead.
 *
 * That substitution belongs here — in the harness — and not in `workers/supervisor.ts`. A
 * production process must not be switchable onto a fake host by setting an environment variable,
 * because the environment is data and "verify against the kernel" is not a decision data may make.
 * The production entrypoint supplies only real seams; this one supplies the fixture, and it is
 * never installed in an image.
 *
 * What is *not* faked: the supervisor's own logic, sockets, authentication, journal, lifecycle and
 * every daemon interaction. Only "which cgroup is this PID in" and "where is the cgroup2 mount"
 * come from the fixture. The PID start time stays the kernel's answer, because it is read from
 * `/proc` regardless of the cgroup question, and mocking it would weaken the identity check rather
 * than relocate its evidence.
 */

import { CgroupFixture, fixtureMembership } from "../../src/lib/execution/cgroup-fixture";
import { readProcessStartTimeTicks } from "../../src/lib/execution/host-facts";
import { main, productionSeams } from "../../workers/supervisor";

const root = process.env.DIP_TEST_CGROUP_FIXTURE ?? "";
if (root === "") {
  process.stderr.write("FATAL: DIP_TEST_CGROUP_FIXTURE is required by the fixture entrypoint\n");
  process.exit(1);
}

const fixture = new CgroupFixture(root);

void main({
  ...productionSeams(),
  // No cgroup driver here, and that is not an omission. Preflight *reads* the container's cgroup
  // from `/proc/<pid>/cgroup` and corroborates it against the mount; it never derives a path from a
  // naming convention, so the driver has nothing to tell it. The driver matters to the watchdog,
  // which must decide whether the path it is shown is the one the configured daemon would create.
  hostFacts: {
    startTimeTicks: readProcessStartTimeTicks,
    cgroupMembership: (pid) => fixtureMembership(root, pid),
    cgroup2Mount: () => fixture.mount(),
  },
});
