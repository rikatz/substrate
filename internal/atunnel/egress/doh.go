// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"go.ate.dev/substrate/internal/doh"
)

// DoHClient exchanges DNS queries with the egress gateway's DoH endpoint. It
// presents the actor's certificate on the same mTLS listener every egress
// connection uses, with the ate-doh ALPN selecting the gateway's DoH filter
// chain, so the actor behind a query is authenticated exactly as behind a
// CONNECT and the gateway decides the query against that actor's
// EgressPolicy.
type DoHClient struct {
	transport *http.Transport
}

// NewDoHClient builds a client from the same configuration a CONNECT client
// takes: the gateway address, its server name, the actor certificate source,
// and the trust bundle for the gateway's serving cert.
func NewDoHClient(cfg ClientConfig) (*DoHClient, error) {
	if _, _, err := net.SplitHostPort(cfg.GatewayAddress); err != nil {
		return nil, fmt.Errorf("egress: invalid egress gateway address %q: %w", cfg.GatewayAddress, err)
	}
	if cfg.ServerName == "" {
		return nil, fmt.Errorf("egress: egress gateway server name is required")
	}
	if cfg.GetClientCertificate == nil {
		return nil, fmt.Errorf("egress: client certificate source is required")
	}
	if cfg.TrustBundlePath == "" {
		return nil, fmt.Errorf("egress: trust bundle path is required")
	}
	trustPEM, err := os.ReadFile(cfg.TrustBundlePath)
	if err != nil {
		return nil, fmt.Errorf("egress: reading trust bundle: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(trustPEM) {
		return nil, fmt.Errorf("egress: trust bundle %s holds no certificate", cfg.TrustBundlePath)
	}
	tlsConfig := &tls.Config{
		ServerName:           cfg.ServerName,
		RootCAs:              rootCAs,
		GetClientCertificate: cfg.GetClientCertificate,
		// The ate-doh token must come first: Envoy selects this client's
		// filter chain by it. h2 lets many queries share one connection.
		NextProtos: []string{doh.ALPN, "h2"},
		MinVersion: tls.VersionTLS12,
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The URL names the DoH host, a routing token; the connection
			// goes to the configured gateway address.
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, cfg.GatewayAddress)
			if err != nil {
				return nil, fmt.Errorf("egress: dialing the egress gateway: %w", err)
			}
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("egress: DoH handshake with the egress gateway: %w", err)
			}
			return tlsConn, nil
		},
	}
	return &DoHClient{transport: transport}, nil
}

// Exchange sends one DNS query and returns the answer. The answer carries
// the query's transaction ID, so the caller hands it to the actor unchanged.
func (c *DoHClient) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+doh.Host+doh.Path, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", doh.ContentType)
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("egress: DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("egress: DoH endpoint answered %s", resp.Status)
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, doh.MaxQueryBytes))
	if err != nil {
		return nil, fmt.Errorf("egress: reading the DoH answer: %w", err)
	}
	return answer, nil
}

// Close drops the idle connections the transport pooled.
func (c *DoHClient) Close() {
	c.transport.CloseIdleConnections()
}
