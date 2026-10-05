package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/grokify/mogo/fmt/fmtutil"
	flags "github.com/jessevdk/go-flags"

	"github.com/grokify/gotrivy"
)

type Options struct {
	Input  string `short:"i" long:"input" description:"Path to scan with trivy fs" required:"true"`
	Output string `short:"o" long:"output" description:"XLSX output file"`
}

func main() {
	opts := Options{}
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(opts.Output) == "" {
		_, f := filepath.Split(opts.Input)
		opts.Output = f + ".xlsx"
	}

	fmt.Printf("INPUT: %s\n", opts.Input)
	report, err := gotrivy.ScanFilepath(context.Background(), opts.Input)
	if err != nil {
		log.Fatal(err)
	}

	rx := gotrivy.Report{Report: &report}
	fmt.Printf("RES COUNT (%d)\n", rx.ResultsCount())
	fmt.Printf("VLN COUNT (%d)\n", rx.VulnerabilityCount())
	fmtutil.MustPrintJSON(rx.SeverityCounts())

	ts, err := rx.TableSet(true)
	if err != nil {
		log.Fatal(err)
	}
	err = ts.WriteXLSX(opts.Output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("DONE")
}
