# Encode and Decode secure cookies

This package provides functions to encode and decode secure cookie values.

A secure cookie has its value encryted along with a MAC. This prevents the 
remote cookie owner to know what information is stored in the cookie and 
to modify it. It also prevent an attacker to forge a fake cookie.

If you consider using secure cookie for authentication, take the time to
read the last section [Authentication with secure cookies](#authentication-with-secure-cookies).

**Warning:** Because this package impacts security of web applications, 
it is a critical functionaly. It still need reviews to be production ready. 
Feedback is welcome. 

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

## Benchmarking

Encoding the cookie named "test" with value "some value". See benchmark functions
at the bottom of cookie_test.go file.  

|                |   Chmike |  Gorilla |
| -------------: | -------: | -------: |
|      Value len |       40 |      112 |
|      Set ns/op |     4659 |    20214 |
|      Get ns/op |     3720 |    20224 |
|       Set B/op |      307 |     3324 |
|       Get B/op |      312 |     2784 |
|  Set allocs/op |        5 |       37 |
|  Get allocs/op |        7 |       39 |

## Qualitative comparison with Gorilla's secure cookie

Gorilla is more "expensive", but also superior on multiple aspects.

- Gorilla encodes a timestamp with the encoded value. It checks that the timestamp 
  is in a valid range when decoding. Chmike provides no timestanp checking. It's 
  left to the user to implement.
- Gorilla computes the hmac over the cookie name, the timestamp and the encrypted 
  value. Chmike computes the hmac only on the value. The user has to add the name
  of the cookie in the value if he want it to be validated.
- Gorrilla uses hmac(sha256) which is 32 bytes long. Chmike uses hmac(md5) which
  is only 16 bytes long. Gorilla is thus safer.
- Gorilla uses 16 random bytes as iv. Chmike use only 3 to 5 random bytes to
  randomize the mac used as iv. That is much less entropy.
- Gorilla checks that the value doesn't exceed 4096 bytes, which is the maximum length.
  Chmike doesn't. 

However, there are also some aspects where Gorilla seam to fall short. 

- Gorilla encodes in base64 the encrypted value, then after prepending the timestamp 
  and appending the hmac, encodes the whole byte sequence in base64 again. This double
  base64 encoding is a waste of time and space for the resulting encoding. Chmike
  avoids this. 
- Gorilla has no encoding version field. They can't change the internal encoding to 
  optimize it or enhance it without breaking backward compatibility. Chmike has also
  no encoding version field. 
  
As a conclusion, you have a trade-off to make between security and performance. 
Gorilla is more secure than Chmike's cookie in it's current state. Chmike generate
more compact cookie values, but is also minimalist about security. 

There is room for easy improvement for Chmike's secure cookie. It's on the todo list.
In the mean time, beware that the encoding may change at any time without notice. 
Use a frozen copy of this package for your development. 

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


## Authentication with secure cookies

It is very important to understand that the security is limited to the cookie 
content. Nothing proves that the other data received by the server with a 
secure cookie has been created by the user's request.

When you have properly set the domain path, and HTTPOnly with the 
Secure flag, and use HTTPS, only the user browser can send the cookie. 
But it is still possible for an attacker to trick your browser to send
a request to the site without the user knowledge and consent. This is known as 
a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) attack. 

All it takes is for the attacker to create a page with a form and incite the 
user to click on the validate button. The user's browser will then send the 
form response with it's field values to the site along with the secure cookie ! 

If the form is to send *n* pizzas to the account holder where *n* is a field
value that the mean attacker has set to 10 for instance, the site owner checking 
only the secure cookie validity will assume that the victim ordered 10 pizzas.
It will be very difficult to sort out what happened when the delivery man 
arrives to the user's home with his 10 pizzas.

To avoid this, the solution is to add a way to authenticate the form response.
This is done by adding a hidden field in the form with a random byte sequence,
and set a secure cookie with that byte sequence as value and a validity date
limit. When the user fill that form, the server will receive back the secure 
cookie and the hidden field value. The server then check that they match to 
validate the response. 

An attacker can forge a random byte sequence, but can't forge the secure cookie
that goes with it. 

The above method works with forms, not with REST API like requests because the 
server can't send the random token to the client that can use as challenge. 
For REST API like authenticated transactions, the client and server have to 
both know a secret byte sequence they use to compute a hmac value over the URI,
the method, the data and a message sequence number. They can then authenticate
the message and the source. 

The secret byte sequence can be determined in the authentication transaction 
with public and private keys. There is no need for TLS to securly authenticate
the client and server. A secret cookie is no help here. 
