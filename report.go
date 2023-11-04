package gotrivy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/gocharts/v2/data/table"
)

func ReadFile(filename string) (*Report, error) {
	rept := &types.Report{}
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, rept)
	if err != nil {
		return nil, err
	}
	return &Report{Report: rept}, err
}

// Report is an extended struct for `github.com/aquasecurity/trivy/pkg/types.Report`.
type Report struct {
	*types.Report
}

func (rm *Report) ResultsCount() int {
	if rm.Report == nil {
		return -1
	} else {
		return len(rm.Report.Results)
	}
}

// SeverityCounts returns the number of vulnerabiltiies detected by severity.
func (rm *Report) SeverityCounts() map[string]uint {
	counts := map[string]uint{}
	for _, res := range rm.Report.Results {
		for _, vln := range res.Vulnerabilities {
			sev := vln.Vulnerability.Severity
			counts[sev]++
		}
	}
	return counts
}

func (rm *Report) VulnerabilityCount() int {
	if rm.Report == nil {
		return -1
	}
	count := 0
	for _, res := range rm.Report.Results {
		count += len(res.Vulnerabilities)
	}
	return count
}

func (rm *Report) TableSet() (*table.TableSet, error) {
	ts := table.NewTableSet("Report")
	counts := rm.SeverityCounts()
	hCounts := histogram.NewHistogram("Vulnerability Counts")
	for sev, cnt := range counts {
		hCounts.Add(sev, int(cnt))
	}
	tblCounts := hCounts.Table("Severity", "Vulnerability Count")
	tblCounts.Name = "Counts by Sev"
	ts.TableMap["Counts"] = tblCounts

	tblVulns, err := rm.Table()
	if err != nil {
		return nil, err
	}
	name := "Detected Vulnerabilities"
	tblVulns.Name = name
	ts.TableMap[name] = tblVulns
	return ts, nil
}

// Table returns a table of vulnerabilities with a column for result set.
// It is formatted with Markdown links which can be rendered in XLSX
// using `github.com/grokify/gocharts/data/table`.
func (rm *Report) Table() (*table.Table, error) {
	tbl := table.NewTable("Vulnerability Report")
	tbl.FormatMap = map[int]string{
		3: table.FormatURL,
	}
	tbl.Columns = []string{
		"Target",
		"Library",
		"Library Path",
		"Vulnerability",
		"Severity",
		"Installed Version",
		"Fixed Version",
		"Title",
	}

	for _, res := range rm.Report.Results {
		target := res.Target
		for _, vln := range res.Vulnerabilities {
			vUIDInfoLink := vln.VulnerabilityID
			if vln.PrimaryURL != "" {
				vUIDInfoLink = fmt.Sprintf("[%s](%s)", vln.VulnerabilityID, vln.PrimaryURL)
			}
			tbl.Rows = append(tbl.Rows, []string{
				target,
				vln.PkgName,
				vln.PkgPath,
				vUIDInfoLink,
				vln.Vulnerability.Severity,
				vln.InstalledVersion,
				vln.FixedVersion,
				vln.Title,
			})
		}
	}
	return &tbl, nil
}

func DetectedVulnerabilitiesTable(vulns []types.DetectedVulnerability) (*table.Table, error) {
	tbl := table.NewTable("Detected Vulnerabilities")
	tbl.Columns = []string{
		"Library",
		"Library Path",
		"Vulnerability",
		"Severity",
		"Installed Version",
		"Fixed Version",
		"Title",
	}

	for _, vln := range vulns {
		vUIDInfoLink := vln.VulnerabilityID
		if vln.PrimaryURL != "" {
			vUIDInfoLink = fmt.Sprintf("[%s](%s)", vln.VulnerabilityID, vln.PrimaryURL)
		}
		tbl.Rows = append(tbl.Rows, []string{
			vln.PkgName,
			vln.PkgPath,
			vUIDInfoLink,
			vln.Vulnerability.Severity,
			vln.InstalledVersion,
			vln.FixedVersion,
			vln.Title,
		})
	}
	return &tbl, nil
}

/* Example:
┌──────────────────┬────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│     Library      │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                           Title                            │
├──────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ follow-redirects │ CVE-2022-0155  │ HIGH     │ 1.14.6            │ 1.14.7        │ follow-redirects: Exposure of Private Personal Information │
│                  │                │          │                   │               │ to an Unauthorized Actor                                   │
│                  │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2022-0155                  │
├──────────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ glob-parent      │ CVE-2020-28469 │ CRITICAL │ 3.1.0             │ 5.1.2         │ nodejs-glob-parent: Regular expression denial of service   │
│                  │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2020-28469                 │
└──────────────────┴────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────────┘
*/
