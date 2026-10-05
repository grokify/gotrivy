package gotrivy

import (
	"fmt"
	"strings"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// FindingSpecOptions configures conversion of Trivy output to findingspec.
type FindingSpecOptions struct {
	// Repo sets Location.Repo for multi-repo/workspace sweeps, optional.
	Repo string
}

// Findings converts the Trivy report into a findingspec.FindingSet of normalized
// security vulnerability findings.
func (r *Report) Findings(opts FindingSpecOptions) *findingspec.FindingSet {
	set := findingspec.NewFindingSet()
	if r.Report == nil {
		return set
	}
	art := r.artifactContext()
	for _, res := range r.Report.Results {
		for _, v := range res.Vulnerabilities {
			set.Add(ToFinding(res, v, art, opts))
		}
	}
	return set
}

// artifactContext derives the container artifact template for the report. It
// returns nil for a non-container (SCA / filesystem) scan, in which case each
// finding is typed as security.TypeSCA.
func (r *Report) artifactContext() *security.Artifact {
	md := r.Report.Metadata
	isContainer := len(md.RepoTags) > 0 || r.Report.ArtifactType == ftypes.TypeContainerImage
	if !isContainer {
		return nil
	}
	art := &security.Artifact{}
	if len(md.RepoTags) > 0 {
		art.Image = md.RepoTags[0]
	} else {
		art.Image = r.Report.ArtifactName
	}
	if len(md.RepoDigests) > 0 {
		art.ImageDigest = md.RepoDigests[0]
	}
	if md.OS != nil {
		art.OS = strings.TrimSpace(string(md.OS.Family) + " " + md.OS.Name)
	}
	return art
}

// ToFinding converts a single Trivy DetectedVulnerability (within its Result and
// report artifact context) into a findingspec.Finding. A non-nil art marks the
// finding as a container scan (type "container"); nil means an SCA scan.
func ToFinding(res trivytypes.Result, v trivytypes.DetectedVulnerability, art *security.Artifact, opts FindingSpecOptions) findingspec.Finding {
	cvss := bestCVSS(v.CVSS)

	var score float64
	if cvss != nil {
		score = cvss.Score
	}

	vuln := security.Vulnerability{
		ID:          fmt.Sprintf("%s:%s@%s:%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion, res.Target),
		Title:       vulnTitle(v),
		Description: v.Description,
		CVEs:        cveIDs(v.VulnerabilityID),
		CWEs:        v.CweIDs,
		CVSS:        cvss,
		Severity:    security.SeverityOrCVSS(v.Severity, score),
		Package:     packageFrom(res, v),
		Fix:         fixFrom(v),
		Component:   v.PkgName + "@" + v.InstalledVersion,
		References:  referencesFrom(v),
	}
	if opts.Repo != "" {
		vuln.Location = &findingspec.Location{Repo: opts.Repo}
	}
	if art != nil {
		a := *art
		a.Layer = layerID(v.Layer)
		vuln.Artifact = &a
		vuln.Type = security.TypeContainer
	} else {
		vuln.Type = security.TypeSCA
	}

	f := vuln.ToFinding()
	f.RuleID = v.VulnerabilityID // preserve the scanner's vuln ID (CVE, GHSA, ALAS, …)
	f.Source = findingspec.Source{Tool: "trivy"}
	return f
}

func vulnTitle(v trivytypes.DetectedVulnerability) string {
	if v.Title != "" {
		return v.Title
	}
	switch {
	case v.VulnerabilityID != "" && v.PkgName != "":
		return fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName)
	case v.VulnerabilityID != "":
		return v.VulnerabilityID
	default:
		return "Vulnerability"
	}
}

// cveIDs returns the vuln ID as a CVE list only when it is a CVE identifier.
func cveIDs(id string) []string {
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return []string{id}
	}
	return nil
}

func packageFrom(res trivytypes.Result, v trivytypes.DetectedVulnerability) *security.Package {
	p := &security.Package{
		Name:      v.PkgName,
		Version:   v.InstalledVersion,
		Path:      v.PkgPath,
		Ecosystem: string(res.Type),
	}
	if v.PkgIdentifier.PURL != nil {
		p.PURL = v.PkgIdentifier.PURL.String()
		if p.Ecosystem == "" {
			p.Ecosystem = v.PkgIdentifier.PURL.Type
		}
	}
	return p
}

// bestCVSS selects a CVSS entry (preferring source "nvd", else any) and maps it
// to security.CVSS, preferring v4.0, then v3.x, then v2.0 within the entry.
func bestCVSS(m dbtypes.VendorCVSS) *security.CVSS {
	if len(m) == 0 {
		return nil
	}
	if c, ok := m["nvd"]; ok {
		return mapCVSS(c)
	}
	for _, c := range m {
		return mapCVSS(c)
	}
	return nil
}

func mapCVSS(c dbtypes.CVSS) *security.CVSS {
	switch {
	case c.V40Vector != "" || c.V40Score != 0:
		return &security.CVSS{Version: "4.0", Vector: c.V40Vector, Score: c.V40Score}
	case c.V3Vector != "" || c.V3Score != 0:
		return &security.CVSS{Version: "3.x", Vector: c.V3Vector, Score: c.V3Score}
	case c.V2Vector != "" || c.V2Score != 0:
		return &security.CVSS{Version: "2.0", Vector: c.V2Vector, Score: c.V2Score}
	default:
		return nil
	}
}

func fixFrom(v trivytypes.DetectedVulnerability) *security.Fix {
	if v.FixedVersion != "" {
		return &security.Fix{State: security.FixStateFixed, Versions: strings.Split(v.FixedVersion, ", ")}
	}
	switch v.Status {
	case dbtypes.StatusWillNotFix, dbtypes.StatusEndOfLife:
		return &security.Fix{State: security.FixStateWontFix}
	case dbtypes.StatusAffected, dbtypes.StatusFixDeferred:
		return &security.Fix{State: security.FixStateNotFixed}
	default:
		return nil
	}
}

func referencesFrom(v trivytypes.DetectedVulnerability) []findingspec.Reference {
	var refs []findingspec.Reference
	if v.PrimaryURL != "" {
		refs = append(refs, findingspec.Reference{URL: v.PrimaryURL})
	}
	for _, u := range v.References {
		refs = append(refs, findingspec.Reference{URL: u})
	}
	return refs
}

func layerID(l ftypes.Layer) string {
	if l.DiffID != "" {
		return l.DiffID
	}
	return l.Digest
}
