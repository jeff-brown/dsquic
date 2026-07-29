// An hq-interop client on quic-go, used as an interop peer in tests.
// Writes each response body to <output-dir>/<basename of path>.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:14433", "server address")
	caFile := flag.String("ca", "", "PEM trust anchor")
	serverName := flag.String("server-name", "localhost", "SNI name")
	outputDir := flag.String("output-dir", ".", "where to write bodies")
	paths := flag.String("paths", "/index.html", "comma separated paths")
	flag.Parse()

	pool := x509.NewCertPool()
	pem, err := os.ReadFile(*caFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read ca:", err)
		os.Exit(1)
	}
	if !pool.AppendCertsFromPEM(pem) {
		fmt.Fprintln(os.Stderr, "ca file contained no certificates")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, *addr, &tls.Config{
		RootCAs:    pool,
		ServerName: *serverName,
		NextProtos: []string{"hq-interop"},
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}

	for _, path := range strings.Split(*paths, ",") {
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open stream:", err)
			os.Exit(1)
		}
		if _, err := stream.Write([]byte("GET " + path + "\r\n")); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
		stream.Close()
		body, err := io.ReadAll(stream)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		target := filepath.Join(*outputDir, filepath.Base(path))
		if err := os.WriteFile(target, body, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write file:", err)
			os.Exit(1)
		}
		fmt.Printf("%s %d\n", path, len(body))
	}
	conn.CloseWithError(0, "")
}
