# Encode and Decode secure cookie value on the server side

This package provides functions to encode and decode value for use as secure cookie.
The user provided value is encrypted and the base64 encoding is stored as value
transmitted to the user agent. The encoding algorithm is described below.

To intall the cookie package use the instruction:

    go get "github.com/chmike/cookie"


## Usage example 

To use this cookie package in your project:

    import "github.com/chmike/cookie"

### Generating a random key

    var key []byte = cookie.GenerateRandomKey()

### Adding a secure cookie to a server response

    cookie := Cookie{
        Name:     "test",
		Value:    "my secret cookie value",
		Path:     "path",
		Domain:   "example.com",
		HTTPOnly: true,
		Secure:   true,
    }
 	err := SetSecure(w, &cookie, key) // w is the http.ResponseWriter

### Decoding a secure cookie value

    value, err := GetSecureValue(r, "test", key) // r is *http.Request



The encoded value is appended to a given buffer, as well as the decoded value.

The encoding is designed to be compact and applies the following pattern : 

    clear text: [value][rnd][mac]

The valus is a copy of the input bytes. rnd is a sequence of 3 to 5 random bytes. 
The number is picked so that the length of the clear text is a multiple of 3. This
simplifies the base64 encoding and decoding, and avoids the need of padding. The
mac is a md5 hmac. The number of random bytes is encoded in the two less significant 
bits of the last random byte. 0 -> 3 random bytes, 1 -> 4, 2 -> 5.

The mac is first encrypted and the result is used as iv for encrypting the rest of
the clear text with aes and CTR block chaining.

The use of the encrypted mac as iv ensures that it is a randomized value. The random
bytes ensure that a same value won't yield an identical cipher text. 

Decoding the value inverse these operations. Multiple validity checs are performed.


SetSecureCookie() example:

    func SetSecureCookie(w http.ResponseWriter, c *http.Cookie, key []byte) error {
        buf := make([]byte, 0, 512) // better use sync.Pool
        buf = append(buf, "Auth="...)
        buf, err := AppendEncodedStringValue(buf, c.Value, key)
        if err != nil {
            return err
        }
        if c.Path != "" {
            buf = append(buf, "; Path="...)
            buf = append(buf, c.Path...)
        }
        if c.Domain != "" {
            buf = append(buf, "; Domain="...)
            buf = append(buf, c.Domain...)
        }
        if c.HttpOnly {
            buf = append(buf, "; HttpOnly"...)
        }
        if c.Secure {
            buf = append(buf, "; Secure"...)
        }
        w.Header().Add("Set-Cookie", *(*string)(unsafe.Pointer(&buf)))
        return nil
    }

To decode the value use the DecodeStringValue function. 

    func GetSecureCookieValue(r http.Request, name string, key []byte) (string, error) {
        c, err := r.Cookie(name)
        if err != nil {
            return "", err
        }
        return DecodeStringValue(c.Value, key)
    }

If there is a validity time limit for the cookie, store them in the value because the user agent
can't be trusted. The secured value may be a string (e.g. JSON) or a byte slice (e.g.Gob).