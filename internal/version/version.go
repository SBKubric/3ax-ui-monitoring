// Package version holds the one build-time string both binaries in this
// module stamp their release with (mon-client sends it as ClientInfo.Version
// on every heartbeat, protocol §5.3; mon-server prints it via `mon-server
// version`). It is a separate package rather than living in
// internal/config — which already had its own version var for mon-server —
// so that internal/client/** (which must never import mon-server packages,
// architecture brief §1) has something to stamp its own build with.
package version

// version is stamped by the release build via
// -ldflags "-X github.com/SBKubric/3ax-ui-monitoring/internal/version.version=<tag>"
// (Makefile LDFLAGS). "dev" is what every non-release build reports —
// `go build ./...` in CI included — so an unstamped binary is unmistakable
// in a heartbeat or a `version` command's output.
var version = "dev"

// Version returns the build-time version string.
func Version() string { return version }
