package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/chmike/securecookie"
)

// Full web server example setting and retrieving a cookie named "myCookie".
// Save the main.go file in some directory, and add a go.mod file by invoking the
// command "go mod init example.com". Run the server with the command "go run main.go".
// With your browser, request url "http://localhost:8080/set/someValue"
// to assign the value "someValue" to the secure cookie named "myCookie" sent to the browser.
// To retrieve the cookie, request url "http://localhost:8080/val".
// The key to secure the cookie will be saved in the file named "key.dat" in the current directory.

// generateNewKey generates and save new key in file with name name.
func generateNewKey(name string) error {
	key, err := securecookie.GenerateRandomKey()
	if err != nil {
		return err
	}
	os.Remove(name)
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(key); err != nil {
		return err
	}
	f.Close()
	return nil
}

// loadKey loads the key saved in file named name. A new key is generated and saved
// in a file named name if the file does not exist.
func loadKey(name string) ([]byte, error) {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		if err := generateNewKey(name); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	key := make([]byte, securecookie.KeyLen)
	n, err := f.Read(key)
	if err != nil {
		return nil, err
	}
	if n != securecookie.KeyLen {
		return nil, fmt.Errorf("key lenght is %d, it should be %d", n, securecookie.KeyLen)
	}
	return key, nil
}

func main() {
	key, err := loadKey("key.dat")
	if err != nil {
		log.Fatal("load key:", err)
	}

	myCookie := securecookie.MustNew("myCookie", key, securecookie.Params{
		Path:     "/val",      // cookie to be sent back only when URL starts with this path
		Domain:   "localhost", // cookie to be sent back only when URL domain matches this one
		MaxAge:   3600,        // cookie becomes invalid 3600 seconds after it is set
		HTTPOnly: true,        // disallow access by remote javascript code
		Secure:   false,       // cookie received with HTTP for testing purpose
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
		val, err := myCookie.GetValue(nil, r)
		if err != nil {
			fmt.Fprintf(w, "unexpected error: %s", html.EscapeString(err.Error()))
			return
		}
		fmt.Fprintf(w, "The value of cookie '%s' is '%s'", myCookie.Name(), html.EscapeString(string(val)))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
