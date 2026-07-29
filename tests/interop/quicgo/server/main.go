// An hq-interop server on quic-go, used as an interop peer in tests.
//
// Only the wiring is ours: every protocol decision belongs to quic-go.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/quic-go/quic-go"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:14434", "listen address")
	certFile := flag.String("cert", "", "PEM certificate chain")
	keyFile := flag.String("key", "", "PEM private key")
	www := flag.String("www", "www", "document root")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load keypair:", err)
		os.Exit(1)
	}
	listener, err := quic.ListenAddr(*addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"hq-interop"},
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Println("ready")
	os.Stdout.Sync()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		go serveConn(conn, *www)
	}
}

func serveConn(conn *quic.Conn, www string) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			request, err := io.ReadAll(stream)
			if err != nil {
				return
			}
			var body []byte
			line := strings.TrimSpace(string(request))
			if path, found := strings.CutPrefix(line, "GET "); found {
				body, _ = os.ReadFile(filepath.Join(www, filepath.Clean("/"+path)))
			}
			// hq-interop has no status codes: a missing file is an empty body.
			stream.Write(body)
			stream.Close()
		}()
	}
}
