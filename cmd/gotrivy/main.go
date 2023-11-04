package main

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/grokify/gotrivy"
	"github.com/grokify/mogo/fmt/fmtutil"
	flags "github.com/jessevdk/go-flags"
)

type Options struct {
	Input  string `short:"i" long:"input" description:"Trivy JSON Report file" required:"true"`
	Output string `short:"o" long:"output" description:"XSLX file"`
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
	r, err := gotrivy.ReadFile(opts.Input)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("RES COUNT (%d)\n", r.ResultsCount())
	fmt.Printf("VLN COUNT (%d)\n", r.VulnerabilityCount())
	fmtutil.PrintJSON(r.SeverityCounts())

	ts, err := r.TableSet()
	if err != nil {
		log.Fatal(err)
	}
	err = ts.WriteXLSX(opts.Output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("DONE")
}
