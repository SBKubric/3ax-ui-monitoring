package app

import "encoding/pem"

// decodePEM returns the DER bytes of the first CERTIFICATE block in b, and the
// remainder. It is split out so the certificate reading in app.go stays about
// what it means rather than about PEM framing.
func decodePEM(b []byte) (der []byte, rest []byte) {
	for {
		block, remainder := pem.Decode(b)
		if block == nil {
			return nil, remainder
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, remainder
		}
		b = remainder
	}
}
