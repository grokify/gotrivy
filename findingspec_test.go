package gotrivy

import (
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

func sampleReport() *Report {
	return &Report{Report: &trivytypes.Report{
		ArtifactName: "alpine:3.19",
		ArtifactType: ftypes.TypeContainerImage,
		Metadata: trivytypes.Metadata{
			OS:          &ftypes.OS{Family: "alpine", Name: "3.19.0"},
			RepoTags:    []string{"alpine:3.19"},
			RepoDigests: []string{"alpine@sha256:abc"},
		},
		Results: trivytypes.Results{
			{
				Target: "alpine:3.19 (alpine 3.19.0)",
				Class:  trivytypes.ClassOSPkg,
				Type:   "alpine",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2024-1234",
						PkgName:          "openssl",
						InstalledVersion: "1.1.1k",
						FixedVersion:     "1.1.1w",
						PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2024-1234",
						Layer:            ftypes.Layer{DiffID: "sha256:layer1"},
						Vulnerability: dbtypes.Vulnerability{
							Title:       "openssl flaw",
							Description: "A flaw in openssl",
							Severity:    "HIGH",
							CweIDs:      []string{"CWE-79"},
							References:  []string{"https://example.com/advisory"},
							CVSS: dbtypes.VendorCVSS{
								"nvd": dbtypes.CVSS{V3Vector: "CVSS:3.1/AV:N/AC:L", V3Score: 7.5},
							},
						},
					},
				},
			},
		},
	}}
}

func TestFindings(t *testing.T) {
	set := sampleReport().Findings(FindingSpecOptions{Repo: "acme/app"})
	if set.Len() != 1 {
		t.Fatalf("Len = %d; want 1", set.Len())
	}

	f := set.Findings[0]
	if err := f.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if f.Domain != findingspec.DomainSecurity || f.Type != security.TypeContainer {
		t.Errorf("domain/type = %s/%s; want security/container", f.Domain, f.Type)
	}
	if f.Source.Tool != "trivy" {
		t.Errorf("source = %q; want trivy", f.Source.Tool)
	}
	if f.RuleID != "CVE-2024-1234" {
		t.Errorf("ruleID = %q; want CVE-2024-1234", f.RuleID)
	}
	if f.Severity != findingspec.SeverityHigh {
		t.Errorf("severity = %q; want high", f.Severity)
	}

	d, err := findingspec.DetailAs[security.VulnerabilityDetail](f)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if d.Package == nil || d.Package.Name != "openssl" || d.Package.Ecosystem != "alpine" {
		t.Errorf("package detail = %+v", d.Package)
	}
	if d.CVSS == nil || d.CVSS.Score != 7.5 || d.CVSS.Version != "3.x" {
		t.Errorf("cvss detail = %+v", d.CVSS)
	}
	if d.Fix == nil || d.Fix.State != security.FixStateFixed || len(d.Fix.Versions) != 1 {
		t.Errorf("fix detail = %+v", d.Fix)
	}
	if d.Artifact == nil || d.Artifact.Image != "alpine:3.19" || d.Artifact.ImageDigest != "alpine@sha256:abc" {
		t.Errorf("artifact detail = %+v", d.Artifact)
	}
	if d.Artifact != nil && d.Artifact.Layer != "sha256:layer1" {
		t.Errorf("artifact layer = %q; want sha256:layer1", d.Artifact.Layer)
	}
	if len(d.CWEs) != 1 || d.CWEs[0] != "CWE-79" {
		t.Errorf("cwes = %+v", d.CWEs)
	}
}
