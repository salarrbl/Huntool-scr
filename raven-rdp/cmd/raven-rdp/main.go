// RavenRDP — RDP Credential Auditor.
//
// An authorized RDP credential-auditing and exposure-testing tool for
// systems the operator owns or is explicitly authorized to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/salarrbl/raven-rdp/internal/app"
	"github.com/salarrbl/raven-rdp/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	res, err := cli.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(cli.Help())
			fmt.Println()
			return 0
		}
		fmt.Fprintln(os.Stderr, "raven-rdp:", err)
		fmt.Fprintln(os.Stderr, "run 'raven-rdp --help' for usage")
		return 2
	}

	if res.ShowVersion {
		fmt.Println(cli.Info())
		return 0
	}

	a, err := app.New(res.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "raven-rdp:", err)
		return 2
	}

	return a.Run(context.Background())
}
