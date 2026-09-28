package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	root := f.String("verified-root", "", "verified root descriptor")
	release := f.String("release-fact", "", "release fact")
	key := f.String("key-fact", "", "key fact")
	enable := f.String("enablement-digest", "", "signed enablement identity")
	_ = f.Parse(os.Args[1:])
	if *root == "" || *release == "" || *key == "" || *enable == "" {
		fmt.Fprintln(os.Stderr, "provider disabled: verified paths and signed enablement are required")
		os.Exit(2)
	}
	for _, p := range []string{*root, *release, *key} {
		if !filepath.IsAbs(p) {
			fmt.Fprintln(os.Stderr, "paths must be absolute")
			os.Exit(2)
		}
	}
	fmt.Println("provider daemon disabled; no listener started")
}
