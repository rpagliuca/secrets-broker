// secrets-broker-web is the phone panel of the broker (package web).
package main

import (
	"os"

	"github.com/rpagliuca/secrets-broker/web"
)

func main() {
	os.Exit(web.Main(os.Args, web.Options{}, os.Stdin, os.Stdout, os.Stderr))
}
