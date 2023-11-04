# GoTrivy

![](logo_gotrivy.png "")

[![Build Status][build-status-svg]][build-status-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

`gotrivy` is a Golang helper for [`github.com/aquasecurity/trivy`](https://github.com/aquasecurity/trivy) ([reference](https://pkg.go.dev/github.com/aquasecurity/trivy)).

The primary purpose of this library is currently to create XSLX reports from a JSON report file. This can be run from the CLI as `cmd/gotrivy/main.go` or it can be done programmatically by inspecting the code of that file.

`gotrivy.Report` is an extension of [`github.com/aquasecurity/trivy/pkg/types.Report`](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types#Report).

## Installation

`go install github.com/grokify/cmd/gotrivy`

## Usage

`gotrivy -i <path-to-report.json> [-o path-to-report.xlsx]`

If an output file isn't provided, a default output filename and path is used setting the filename to the original filename with a `.xlsx` suffix in the current directory.

 [build-status-svg]: https://github.com/grokify/gotrivy/workflows/test/badge.svg
 [build-status-url]: https://github.com/grokify/gotrivy/actions/workflows/test.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/gotrivy
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/gotrivy
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/gotrivy
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/gotrivy
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/gotrivy/blob/master/LICENSE
