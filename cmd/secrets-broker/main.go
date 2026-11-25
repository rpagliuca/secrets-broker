// Command secrets-broker is the reference binary: age-encrypted directory as
// the store, a tokens file as the authenticator, JSON lines on standard
// output as the audit log, approval through the control socket.
package main

import "github.com/rpagliuca/secrets-broker/cli"

func main() { cli.Main(nil) }
