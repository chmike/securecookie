# Encode and Decode secure cookies

This package provides functions to encode and decode secure cookie values.

A secure cookie has its value encryted with a MAC so that the value can 
be autenticated when decoded. The encryption and authentication allows
to stone sensible information in the cookie that can be accessed by a
simple decryption. 

It it then possible to store the sequentially assigned user record ID, 
the user role and and expires date. The remote user wont be able to see
or modify that information.

The main benefit is that this information becomes available in the backend
request handler without accessing a shared and persistent storage. This 
avoids a significant source of latency when the server is loaded. 

Another benefit is that some reguest handlers on the server side may 
become fully stateless since the state is safely stored in the cookie 
and transmitted with each request.   


**Warning:** Because this package impacts security of web applications, 
it is critical and still need reviews to be production ready. 
Feedback is welcomed. 

## Installation

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
To mitigate the risk that an attacker get the saved key, store a second key in 
another place and use the xor of both keys as secure cookie key. The attacker 
will have to get both keys which must be more difficult. 

### Instantiating a cookie object

``` Go
params := Params{
    Path:     "/sec",
    Domain:   "example.com", 
    MaxAge:   3600,
    HTTPOnly: true,
    Secure:   true,
}
obj, err := cookie.New(key, "Auth", params)
if err != nil {
    // ...
}
```

### Adding a secure cookie to a server response

``` Go
err = obj.SetSecureValue(w, []byte("some value)) // w is the http.ResponseWriter
if err != nil {
    // ...
}
```

### Decoding a secure cookie value

``` Go
value, err := obj.GetSecureValue(r) // r is the *http.Request
```

The returned value is of type []byte.

### Deleting a cookie

``` Go
err := obj.Delete(r) // r is the *http.Request
```

Note: don't rely on the assumption that the remote user agent will effectively 
delete the cookie. 

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
because of the secret key. It is even harder if the MAC is encrypted. 

The key is 32 byte long. The first 16 bytes are used as hmac key, the last
16 bytes are used as encryption key.  

To encrypt the clear text, the MAC is first encrypted using AES128. The 
length of the MAC is exactly the length of an AES block. The encrypted 
MAC is then used as IV, and the value and random bytes are encrypted using
CTR with AES128.

The resulting ciphered text is then encoded in base64 and stored as value
in the cookie. 

These operations are reversed to decrypt the value.

## Contributors

- lstokeworth (reddit): 
    - suggest to replace `copy` with `append`, 
    - remove the Expires Params field and use only the MaxAge,
    - provide a constant date in the past for Delete.
- cstockton (github): 
    - critical [bug report](https://github.com/chmike/cookie/issues/1),
    - suggest simpler API.