// adapter-rollypay is the mikan payment adapter for RollyPay (protocol v1, PROTOCOL.md).
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

//go:embed adapter.json
var manifestJSON []byte

func main() {
	m, err := catalog.ParseManifest(manifestJSON)
	if err == nil {
		err = adapter.Run(&rollyPay{api: "https://rollypay.io/api/v1", hc: adapter.HTTPClient(), manifest: m})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "adapter-rollypay:", err)
		os.Exit(1)
	}
}
