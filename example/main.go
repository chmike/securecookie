package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chmike/securecookie/v2"
)

// Full HTTPS web server example setting and retrieving a cookie named "myCookie".
// Run the server from the repository root with the command "go run ./example".
// With your browser, request url "https://localhost:8443/set/someValue"
// to assign the value "someValue" to the secure cookie named "myCookie" sent to the browser.
// To retrieve the cookie, request url "https://localhost:8443/val", and to
// delete it, request url "https://localhost:8443/delete". The home page
// "https://localhost:8443/" has links to these pages.
//
// Secure cookies, and thus securecookie, require HTTPS. The server uses a
// self-signed certificate for localhost, generated at each start. The browser
// warns that the certificate is not trusted. Accept the risk to continue.
// The seed of the key store is saved in the file named "seed.dat" in the
// current directory. Servers sharing the same seed decode each other's values.

// loadSeed returns the seed saved in the file named name. A new seed is
// generated and saved in a file named name, readable only by the owner,
// if the file does not exist.
func loadSeed(name string) ([]byte, error) {
	seed, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		if seed, err = securecookie.GenerateSeed(); err != nil {
			return nil, err
		}
		return seed, os.WriteFile(name, seed, 0600)
	}
	return seed, err
}

// selfSignedCert returns a self-signed TLS certificate for localhost, valid
// one year.
func selfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func main() {
	seed, err := loadSeed("seed.dat")
	if err != nil {
		log.Fatal("load seed:", err)
	}
	keys, err := securecookie.NewKeyStore(seed)
	if err != nil {
		log.Fatal("key store:", err)
	}

	// The cookie name becomes "__Host-myCookie", and the cookie is Secure.
	// The cookie value becomes invalid one hour after it is set.
	myCookie := securecookie.MustNew("myCookie", keys, time.Hour)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<title>securecookie example</title>
<h1>securecookie example</h1>
<ul>
<li><a href="/set/someValue">Set the cookie value to "someValue"</a></li>
<li><a href="/val">Get the cookie value</a></li>
<li><a href="/delete">Delete the cookie</a></li>
</ul>`)
	})

	http.HandleFunc("/set/", func(w http.ResponseWriter, r *http.Request) {
		val := "none"
		if pos := strings.LastIndex(r.URL.Path, "/"); pos != -1 && pos != len(r.URL.Path)-1 {
			val = r.URL.Path[pos+1:]
		}
		if err := myCookie.SetValue(w, []byte(val)); err != nil {
			fmt.Fprintf(w, "unexpected error: %s", html.EscapeString(err.Error()))
			return
		}
		fmt.Fprintf(w, "A secure cookie named '%s' with value '%s' has been sent", myCookie.Name(), html.EscapeString(val))
	})

	http.HandleFunc("/val", func(w http.ResponseWriter, r *http.Request) {
		val, stamp, err := myCookie.Value(nil, r)
		if err != nil {
			fmt.Fprintf(w, "error: %s", html.EscapeString(err.Error()))
			return
		}
		fmt.Fprintf(w, "The value of cookie '%s' is '%s', set at %s", myCookie.Name(),
			html.EscapeString(string(val)), stamp.Format(time.RFC3339))
	})

	http.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if err := myCookie.Delete(w); err != nil {
			fmt.Fprintf(w, "unexpected error: %s", html.EscapeString(err.Error()))
			return
		}
		fmt.Fprintf(w, "A request to delete the cookie '%s' has been sent", myCookie.Name())
	})

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatal("certificate:", err)
	}
	srv := &http.Server{
		Addr:      ":8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	fmt.Println("Server listening on https://localhost:8443")
	fmt.Println("Home page:            https://localhost:8443/")
	fmt.Println("Set the cookie value: https://localhost:8443/set/someValue")
	fmt.Println("Get the cookie value: https://localhost:8443/val")
	fmt.Println("Delete the cookie:    https://localhost:8443/delete")
	fmt.Println("The browser warns that the self-signed certificate is not trusted: accept the risk")
	fmt.Println("Stop the server with Ctrl-C")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
