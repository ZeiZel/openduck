package main

import (
	"flag"
	"fmt"
	"os"

	"openduck/internal/releasepublisher"
)

func main() {
	staging := flag.String("staging", "", "private sibling staging directory")
	target := flag.String("target", "", "new published directory")
	flag.Parse()
	if *staging == "" || *target == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: openduck-release-publisher --staging DIR --target DIR")
		os.Exit(2)
	}
	if err := releasepublisher.PublishDirectory(*staging, *target); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
