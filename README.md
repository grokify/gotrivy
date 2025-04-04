<div align="center">

# GoTrivy

![](logo_gotrivy.png "")

[![Build Status][build-status-svg]][build-status-url]
[![Lint Status][lint-status-svg]][lint-status-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

</div>

`gotrivy` is a Golang helper for [`github.com/aquasecurity/trivy`](https://github.com/aquasecurity/trivy) ([reference](https://pkg.go.dev/github.com/aquasecurity/trivy)).

The primary purpose of this library is currently to create XSLX reports from a JSON report file. [Trivy provides reports in Table and JSON formats, along with a custom Template capability](https://aquasecurity.github.io/trivy/v0.17.2/examples/report/). This libary provides an additional XLSX option via [`github.com/grokify/gocharts`](https://github.com/grokify/gocharts). This can be run from the CLI as [`cmd/gotrivy/main.go`](cmd/gotrivy/main.go) or it can be done programmatically by inspecting the code of that file.

[`gotrivy.Report`](https://pkg.go.dev/github.com/grokify/gotrivy#Report) is an extension of [`github.com/aquasecurity/trivy/pkg/types.Report`](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types#Report).

## Installation

`go install github.com/grokify/gotrivy/cmd/gotrivy`

## Usage

`gotrivy -i <path-to-report.json> [-o path-to-report.xlsx]`

If an output file isn't provided, a default output filename and path is used setting the filename to the original filename with a `.xlsx` suffix in the current directory.

## References

### Scan Image

The following is an example of scanning a local image:

```
% docker image ls
REPOSITORY                       TAG       IMAGE ID       CREATED        SIZE
grokify/ringcentral-permahooks   v0.2.3    af80576e5e7d   6 months ago   640MB
% trivy image -f json grokify/ringcentral-permahooks > trivy-report.json
% gotrivy -i trivy-report.json -o trivy-report.xlsx
```

### Scan JAR

```
% trivy -d fs path/to/jar
% trivy -d fs path/to/pom.xml
```

Extract `pom.xml` from JAR file:

```
% unzip myfile.jar pom.xml
```

```
% trivy -d fs pom.xml 
2024-10-30T01:26:21.429-0700	DEBUG	Severities: ["UNKNOWN" "LOW" "MEDIUM" "HIGH" "CRITICAL"]
2024-10-30T01:26:21.429-0700	DEBUG	Ignore statuses	{"statuses": null}
2024-10-30T01:26:21.440-0700	DEBUG	cache dir:  /path/to/Caches/trivy
2024-10-30T01:26:21.440-0700	DEBUG	DB update was skipped because the local DB is the latest
2024-10-30T01:26:21.440-0700	DEBUG	DB Schema: 2, UpdatedAt: 2024-10-30 06:47:03.247108911 +0000 UTC, NextUpdate: 2024-10-31 06:47:03.24710874 +0000 UTC, DownloadedAt: 2024-10-30 07:37:27.722974 +0000 UTC
2024-10-30T01:26:21.440-0700	INFO	Vulnerability scanning is enabled
2024-10-30T01:26:21.440-0700	DEBUG	Vulnerability type:  [os library]
2024-10-30T01:26:21.440-0700	INFO	Secret scanning is enabled
2024-10-30T01:26:21.440-0700	INFO	If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-10-30T01:26:21.440-0700	INFO	Please see also https://aquasecurity.github.io/trivy/v0.46/docs/scanner/secret/#recommendation for faster secret detection
2024-10-30T01:26:21.441-0700	DEBUG	No secret config detected: trivy-secret.yaml
2024-10-30T01:26:21.441-0700	DEBUG	The nuget packages directory couldn't be found. License search disabled
2024-10-30T01:26:21.441-0700	DEBUG	Walk the file tree rooted at 'pom.xml' in parallel
2024-10-30T01:26:21.441-0700	DEBUG	Resolving org.json:json:20220924...
2024-10-30T01:26:21.625-0700	DEBUG	Start parent: org.sonatype.oss:oss-parent:9
2024-10-30T01:26:21.626-0700	DEBUG	Exit parent: org.sonatype.oss:oss-parent:9
2024-10-30T01:26:21.638-0700	DEBUG	OS is not detected.
2024-10-30T01:26:21.638-0700	DEBUG	Detected OS: unknown
2024-10-30T01:26:21.638-0700	INFO	Number of language-specific files: 1
2024-10-30T01:26:21.638-0700	INFO	Detecting pom vulnerabilities...
2024-10-30T01:26:21.638-0700	DEBUG	Detecting library vulnerabilities, type: pom, path: pom.xml

pom.xml (pom)

Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 2, CRITICAL: 0)

┌───────────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬────────────────────────────────────────────┐
│    Library    │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │                   Title                    │
├───────────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼────────────────────────────────────────────┤
│ org.json:json │ CVE-2022-45688 │ HIGH     │ fixed  │ 20220924          │ 20230227      │ json stack overflow vulnerability          │
│               │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2022-45688 │
│               ├────────────────┤          │        │                   ├───────────────┼────────────────────────────────────────────┤
│               │ CVE-2023-5072  │          │        │                   │ 20231013      │ JSON-java: parser confusion leads to OOM   │
│               │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2023-5072  │
└───────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴────────────────────────────────────────────┘
```

## Update Trivy Databases

```
% trivy image --download-db-only
% trivy image --download-java-db-only
% trivy image --reset
```

 [build-status-svg]: https://github.com/grokify/gotrivy/actions/workflows/ci.yaml/badge.svg?branch=master
 [build-status-url]: https://github.com/grokify/gotrivy/actions/workflows/ci.yaml
 [lint-status-svg]: https://github.com/grokify/gotrivy/actions/workflows/lint.yaml/badge.svg?branch=master
 [lint-status-url]: https://github.com/grokify/gotrivy/actions/workflows/lint.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/gotrivy
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/gotrivy
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/gotrivy
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/gotrivy
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/gotrivy/blob/master/LICENSE
