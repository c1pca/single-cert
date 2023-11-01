package onecert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SingleCertGetter{})
}

// SingleCertGetter gets a certificate.
type SingleCertGetter struct {
	// The path to pem file
	Path string `json:"path,omitempty"`

	logger *zap.SugaredLogger
	ctx    context.Context
}

// CaddyModule returns the Caddy module information.
func (scg SingleCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.path",
		New: func() caddy.Module { return new(SingleCertGetter) },
	}
}

func (scg *SingleCertGetter) Provision(ctx caddy.Context) error {
	scg.logger = ctx.Logger().Sugar()
	scg.ctx = ctx
	if scg.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}

func (scg SingleCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	bodyBytes, err := getCertificateFromFile(scg.Path)
	scg.logger.Debugf("GetCertificate path: %s serverName: %s", scg.Path, hello.ServerName)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate: %v", err)
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle(bodyBytes)
	scg.logger.Debugf("certificate cert: %s", cert)
	if err != nil {
		return &cert, err
	}

	return &cert, nil
}

func getCertificateFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//	... cert <path>
func (scg *SingleCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		scg.Path = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			return d.Err("block not allowed here")
		}
	}
	return nil
}

// Ref caddyserver/caddy/modules/caddytls/folderloader.go:84
// This func not exported by caddy
func tlsCertFromCertAndKeyPEMBundle(bundle []byte) (tls.Certificate, error) {
	certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
	var foundKey bool // use only the first key in the file

	for {
		// Decode next block so we can see what type it is
		var derBlock *pem.Block
		derBlock, bundle = pem.Decode(bundle)
		if derBlock == nil {
			break
		}

		if derBlock.Type == "CERTIFICATE" {
			// Re-encode certificate as PEM, appending to certificate chain
			if err := pem.Encode(certBuilder, derBlock); err != nil {
				return tls.Certificate{}, err
			}
		} else if derBlock.Type == "EC PARAMETERS" {
			// EC keys generated from openssl can be composed of two blocks:
			// parameters and key (parameter block should come first)
			if !foundKey {
				// Encode parameters
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}

				// Key must immediately follow
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
					return tls.Certificate{}, fmt.Errorf("expected elliptic private key to immediately follow EC parameters")
				}
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			// RSA key
			if !foundKey {
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else {
			return tls.Certificate{}, fmt.Errorf("unrecognized PEM block type: %s", derBlock.Type)
		}
	}

	certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
	if len(certPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("failed to parse PEM data")
	}
	if len(keyPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("no private key block found")
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("making X509 key pair: %v", err)
	}

	return cert, nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*SingleCertGetter)(nil)
	_ caddy.Provisioner     = (*SingleCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*SingleCertGetter)(nil)
)
