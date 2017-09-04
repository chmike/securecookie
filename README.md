# Encode and Decode secure cookies

This package provides functions to encode and decode cookie values for use as secure cookie.
The encoding algorithm is described below.

To intall or update the cookie package use the instruction:

``` Bash
go get -u "github.com/chmike/cookie"
```

## Usage example 

To use this cookie package in your server, add the following import.

``` Go
import "github.com/chmike/cookie"
```
### Generating a random key

It is strongly recommended to generate the random key with the following function.
Save the key in a file using hex.EncodeToString() and restrict access to that file.

``` Go
var key []byte = cookie.GenerateRandomKey()
```

### Adding a secure cookie to a server response

``` Go
params := cookie.Params{
    Name:     "test",
    Value:    "my secret cookie value",
    Path:     "path",
    Domain:   "example.com",
    Expires:  time.Now().Add(24 * time.Hour),
    HTTPOnly: true,
    Secure:   true,
}
err := cookie.SetSecure(w, &params, key) // w is the http.ResponseWriter
```

While the Value field is of type string, a []byte converted to a string with
the function cookie.BytesToString() may also be assigned to it. This function 
avoids the allocation and copy overhead, but it requires that the value is not
modified after the conversion.

### Decoding a secure cookie value

``` Go
value, err := cookie.GetSecureValue(r, "test", key) // r is *http.Request
```

The returned value is of type []byte, but it can be efficiently converted
to a string with the function cookie.BytesToString(). The key must be the
same key used the set the secure cookie.

### Deleting a cookie

``` Go
params := cookie.Params{
    Name:       "test",
    // Value:    ignored
    Path:       "path",
    Domain:     "example.com",
    // MaxAge:   ignored
    // Expires:  ignored
    HTTPOnly:   true, // Optional, but recommended
    Secure:     true, // Optional, but recommended
}
err := cookie.Delete(w, &params)
```

To delete a cookie, the specification requires that we provide the name,
the path and domain value, and an Expires value in the past. The
Delete function will generate that expires value for your.

The actual values in the Value, MaxAge and Expires fields of the Params
struct are ignored.    

## Value encoding 

The clear text is the concatenation of the value bytes, 3 to 5 random bytes,
and the MAC of 16 bytes. 

    clear text = [value][rnd][mac]

The number of random bytes is picked so that the clear text length is a
multiple of 3 to simplifies the base64 encoding. The two less significant
bits of the last random byte encode the number of random bytes: 0->3, 
1->4 and 2->5. 3 is invalid. 

The mac is an hmac(md5) computed over the value and random bytes. While 
it is easy to forge an md5 collision, forging a valid hmac(md5) is harder 
because of the key. It is even harder if the MAC is encrypted. 

The key is 32 byte long. The first 16 bytes are used as hmac key, the last
16 bytes are used as encryption key.  

To encrypt the clear text, the MAC is first encrypted using AES128. The 
length of the MAC is exactly the length of an AES block. The encrypted 
MAC is then used as IV, and the value and random bytes are encrypted using
CTR with AES128.

The resulting ciphered text is then encoded in base64 and stored as value in
the cookie. 

These operations are reversed to decrypt the value.

## Contributions

- lstokeworth (reddit): suggest to replace `copy` with `append`, simplify by 
  removing the Expires cookie field, and provide a constant date in the past
  for Delete, in reddit discussion.
- cstockton (github): [bug report](https://github.com/chmike/cookie/issues/1) 
  and suggest better API in reddit discussion.