[![GoDoc](https://godoc.org/github.com/chmike/securecookie?status.svg)](https://godoc.org/github.com/chmike/securecookie) [![Build](https://travis-ci.org/chmike/securecookie?branch=master)](https://travis-ci.org/chmike/securecookie) 

# Encode and Decode secure cookies

This package provides functions to encode and decode secure cookie values.

A secure cookie has its value ciphered and signed with a message authentication
code. This prevents the remote cookie owner to know what information is stored 
in the cookie and to modify it. It also prevent an attacker to forge a fake 
cookie.

This package differ from the gorilla secure cookie in that its encoding and
decoding is 3 times faster and needs no heap allocation with an equivalent
security strength. Both use AES128 and SHA256 to secure the value.

**Note:** This package uses its own secure cookie value encoding. It is thus
incompatible with Gorilla secure cookie package and the one provided with other
langage frameworks. This encoding is simpler and more efficient, and adds a
version number to support evolution with backward compatibility. 

**Warning:** Because this package impacts security of web applications,
it is a critical functionaly. It still need reviews to be production ready.
Feedback is welcome.

## Content

- [Installation](#installation)
- [Usage examples](#usage-examples)
- [Benchmarking](#benchmarking)
- [Qualitative comparison](#qualitative-comparison)
- [Value encoding](#value-encoding)
- [Usage advise](#usage-advise)

## Installation

To intall or update this secure cookie package use the instruction:

``` Bash
go get -u "github.com/chmike/securecookie"
```

## Usage examples

To use this cookie package in your server, add the following import.

``` Go
import "github.com/chmike/securecookie"
```

### Generating a random key

It is strongly recommended to generate the random key with the following function.
Save the key in a file using hex.EncodeToString() and restrict access to that file.

``` Go
var key []byte = securecookie.GenerateRandomKey()
```

To mitigate the risk that an attacker get the saved key, you might store a second
key in another place and use the xor of both keys as secure cookie key. The attacker
will have to get both keys to recontruct the effective key which should be more 
difficult.

### Instantiating a cookie object

``` Go
obj, err := securecookie.New("Auth", key, securecookie.Params{
		Path:     "/sec",        // cookie is received only when URL start with this path
		Domain:   "example.com", // cookie is received only when URL domain match this one
		MaxAge:   3600,          // cookie becomes invalid 3600 seconds after it's set
		HTTPOnly: true,          // cookie is inaccessible to remote browser scripts 
		Secure:   true,          // cookie is received only with HTTPS, never with HTTP
})
if err != nil {
    // ...
}
```

It is also possible to instantiate a secure cookie object without returning
an error and panic if an argument is invalid. In the following example,
`Auth` is the cookie name and the Path is `/sec`. A secured value may be stored
in the remote browse by calling the `SetCookie()` method. After that, every 
subsequent requests from that browser with a URL starting with `/sec` will have
the cookie sent along. Calling the method `GetValue()` will extract the  secure
value from the request. A request to delete the cookie may be send to the 
remote browser by calling the method `Delete()`.

``` Go
var obj = securecookie.MustNew("Auth", key, securecookie.Params{
		Path:     "/sec",        // cookie is received only when URL start with this path
		Domain:   "example.com", // cookie is received only when URL domain match this one
		MaxAge:   3600,          // cookie becomes invalid 3600 seconds after it's set
		HTTPOnly: true,          // cookie is inaccessible to remote browser scripts 
		Secure:   true,          // cookie is received only with HTTPS, never with HTTP
}
```

Remember that the key should not be stored in the source code or in a repository.

### Adding a secure cookie to a server response

``` Go
var val = []byte("some value")
// with w as the http.ResponseWriter
if err := obj.SetValue(w, val); err != nil {
    // ...
}
```

### Decoding a secure cookie value

The value is appended to the given buffer. If buf is nil a new buffer is
allocated. If buf is too small it is grown. 

``` Go
// with r as the *http.Request
val, err := obj.GetValue(buf, r) 
if err != nil {
  // ...
}
```

The returned value is of type []byte.

### Deleting a cookie

``` Go
// with r as the *http.Request
if err := obj.Delete(r); err != nil {
  // ...
}
```

Note: don't rely on the assumption that the remote user agent (browser) will
effectively delete the cookie. Evil users will try anything to break your site.

## Benchmarking

Encoding the cookie named "test" with value "some value". See benchmark functions
at the bottom of cookie_test.go file. The ns/op values were obtained by running
the benchmark 10 times and taking the minimal value.

|                |   Chmike |  Gorilla |
| -------------: | -------: | -------: |
|      Value len |       84 |      112 |
|      Set ns/op |     5527 |    14946 |
|      Get ns/op |     4421 |    21142 |
|       Set B/op |      342 |     3322 |
|       Get B/op |      200 |     2784 |
|  Set allocs/op |        3 |       37 |
|  Get allocs/op |        3 |       39 |

The secure cookie value encoding and decoding functions of this package need 0 
heap allocations. 

## Qualitative comparison

The latest version was updated to put the security in line with the Gorilla
secure cookie.

- We both use CTR-AES-128 encryption with a 16 byte nonce, and HMAC-SHA-256.
- We both encrypt first then compute the MAC over the cipher text.
- A time stamp is added to the encoded value.
- The hmac is computed over the cookie value name, the ciphered time stamp and
  value.
- Both packages don't take special measures to secure the secret key.
- Both packages don't effectively conceal the value byte length.

The differences between the Gorilla secure cookie and this implementation are:

- This code is more efficient, and there is still room for improvement.
- This secure value encoding is more compact without weakening the security.
- This secure cookie encoding is incompatible with other secure cookie encoding.
  I don't know the status of Gorilla's encoding.
- This encoding adds an encoding version number allowing to change or add new
  encoding without breaking backward compatibility. Gorilla doesn't have this.
- This package provides a Delete cookie method.

This package and Gorilla provide both equivalently secure cookie if we discard
the fact that no special measure is taken to conceal the key in memory and the
value length. This package is quite new and needs more reviews to validate the
security of the implementation.

Feedback and contributions are welcome.

## Value encoding

1. A clear text mesage is first assembled as follow:

    [tag][nonce][stamp][value][padding]

  - The tag is 1 byte. The 6 most significant bits encode the version number
    of the encoding (currently 0). The 2 less significant bits encode the number
    of padding bytes (0, 1 or 2). 3 is an invalid padding length. The number is
    picked so that the total length including the MAC is a multiple of 3. This
    simplifies base64 encoding by avoiding it's padding.
  - The nonce is 16 byte long (AES block length) and contains cryptographically
    secure pseudo random bytes.
  - The stamp is the unix time subtracted by an epochOffset value (1505230500),
    and encoded using the [LEB128 encoding](https://en.wikipedia.org/wiki/LEB128).
  - The value is a copy of the user provided value to secure.
  - The padding bytes are cryptographically secure pseudo random bytes. There may
    be 0 to 2 padding bytes. The number is picked so that the total length
    including the MAC is a multiple of 3. This simplifies base64 encoding by
    avoiding it's padding.

2. The stamp, value and padding bytes are ciphered using CTR-AES with the 16 last
   bytes of the key as ciphering key. The nonce is used as iv and counter
   initialization value. The tag and nonce are left unciphered.

3. An HMAC-SHA-256 is computed over (1) the cookie name and (2) the bytes sequence
   obtained after step 2. The 32 byte long MAC is appended after the padding.

4. The whole byte sequence, form the tag to the last byte of the MAC is encoded in
   [Base64 using the URL encoding](https://tools.ietf.org/html/rfc4648#section-5).
   There is no padding since the byte length is a multiple of 3 bytes.

The tag which provides an encoding version allows to completely change the encoding
while preserving backward compatibilty if required.

## Contributors

- lstokeworth (reddit):
  - suggest to replace `copy` with `append`,
  - remove the Expires Params field and use only the MaxAge,
  - provide a constant date in the past for Delete.
- cstockton (github):
  - critical [bug report](https://github.com/chmike/cookie/issues/1),
  - suggest simpler API.

## Usage advise

It is very important to understand that the security is limited to the cookie
content. Nothing proves that the other data received by the server with a
secure cookie has been created by the user's request.

When you have properly set the domain path, and HTTPOnly with the
Secure flag, and use HTTPS, only the user browser can send the cookie.
But it is still possible for an attacker to trick your browser to send
a request to the site without the user knowledge and consent. This is known as
a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) attack.

Consider this scenario with a Pizza ordering web site. First let see what
happens when everything goes as expected.

The user has to login the site to be allowed to order pizzas. During the
login transaction a secure cookie is added into the user's browser. The user
is then shown a form with the number of pizzas to order. When the user clicks
the *Order* button, his browser will make a request to an URL provided with
the form. It will join the field values and the secure cookie since the URL
path and domain match the one specified at the login transaction.

When the server receive this request, it checks the cookie validity to
determine who that client is and if he is legitimate. All is fine. The order
is then forwarded to the pizza chef. The pizza is later delivered to the
user.

Now comes the vilain. He set up some random site with a form and a validation
button that the victim will very likely click (e.g., "Subscribe to spam" with
a *Please no* button as validation button). The vilain has set up the form
so that the URL associated to the validation button is the URL to order pizzas.
He will have added a hidden field with the number of pizzas to order set to 10!

When the user click that validation button, his browser will send a request
to pizza ordering site with the field value and the secure cookie since the
URL match the cookie path and domain.

The pizza ordering site checks the secure cookie and it will be authenticated.
It will assume that the user issued that order. When the delevery man rings at
the user's door with 10 pizzas in his hand, there will be a conflict and no way
to know to know who's fault it is. Notice how the value 10 associated with the
cookie to the ordering request was not signed by the user's browser.

To avoid this, the solution is to add a way to authenticate the form response.
This is done by adding a hidden field in the form with a random byte sequence,
and set a secure cookie with that byte sequence as value and a validity date
limit. When the user fill that form, the server will receive back the secure
cookie and the hidden field value. The server then check that they match to
validate the response.

An attacker can forge a random byte sequence, but can't forge the secure cookie
that goes with it.

Note that this protection is void in case of XSS attack (script injection).

The above method works with forms, not with REST API like requests because the
server can't send the random token to the client that can use as challenge.
For REST API like authenticated transactions, the client and server have to
both know a secret byte sequence they use to compute a hmac value over the URI,
the method, the data and a message sequence number. They can then authenticate
the message and the source.

The secret byte sequence can be determined in the authentication transaction
with public and private keys. There is no need for TLS to securly authenticate
the client and server. A secret cookie is no help here.
