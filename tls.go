package browser

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"syscall"
)

const maxIssuerRoots = 64 << 10

// readIssuerRoots loads public trust anchors only. It never modifies system
// trust and intentionally replaces, rather than supplements, the client's roots.
func readIssuerRoots(path string) (*x509.CertPool, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("cannot open issuer roots")
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > maxIssuerRoots {
		return nil, errors.New("issuer roots must be a bounded regular file")
	}
	data, e := io.ReadAll(io.LimitReader(file, maxIssuerRoots+1))
	if e != nil || len(data) > maxIssuerRoots {
		return nil, errors.New("cannot read issuer roots")
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("issuer roots must contain public certificate PEM only")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid issuer certificate PEM")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, errors.New("issuer roots must contain CA certificates")
		}
		count++
		if count > 16 {
			return nil, errors.New("too many issuer roots")
		}
		pool.AddCert(cert)
		data = rest
	}
	if count == 0 {
		return nil, errors.New("issuer root file is empty")
	}
	return pool, nil
}
