// Command openduck-provider-attestor is the root-owned manifest-bound entry
// point for provider attestation. It deliberately refuses standalone
// attestation: a verified result can only be produced in-process while holding
// a sealed macoschannel.Conn, because an inherited numeric FD would discard
// the authenticated transcript and release pins.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	b, code := run()
	fmt.Println(string(b))
	os.Exit(code)
}

func run() ([]byte, int) {
	b, _ := json.Marshal(struct {
		Schema      string `json:"schema"`
		Operational bool   `json:"operational"`
		ReasonCode  string `json:"reason_code"`
	}{"openduck.provider-attestor.v1", false, "authenticated_controller_channel_unavailable"})
	return b, 2
}
