package gotrivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/aquasecurity/trivy/pkg/types"
)

/*
ScanFilepath executes trivy filesystem scan using the trivy command-line tool.
This provides a clean Go API that internally calls the trivy binary.
Equivalent to: trivy fs --format json --scanners vuln <path>

Note: This implementation uses exec.Command instead of direct Go API integration
to avoid pulling Trivy's full scanning dependency tree into every importer. It
requires the trivy binary to be installed and on PATH. The interface remains
identical to what a pure Go API would provide.
*/
func ScanFilepath(ctx context.Context, targetPath string) (types.Report, error) {
	// Build the trivy command with appropriate flags
	args := []string{
		"fs",               // filesystem scan
		"--format", "json", // JSON output for parsing
		"--scanners", "vuln", // only vulnerability scanning
		"--quiet",  // reduce noise
		targetPath, // target path to scan
	}

	// Execute trivy command with context
	cmd := exec.CommandContext(ctx, "trivy", args...)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return types.Report{}, fmt.Errorf("trivy scan failed (exit code %d): %s",
				exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return types.Report{}, fmt.Errorf("trivy scan failed: %w", err)
	}

	// Parse the JSON output into a Trivy Report struct
	var report types.Report
	if err := json.Unmarshal(output, &report); err != nil {
		return types.Report{}, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return report, nil
}
