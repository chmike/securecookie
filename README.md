[![GoDoc](https://img.shields.io/badge/go.dev-reference-blue)](https://pkg.go.dev/github.com/chmike/securecookie/v2)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)
![release](https://img.shields.io/github/release/chmike/securecookie.svg)

# Encode and Decode secure cookies

This package provides functions to encode and decode secure cookie values.

A secure cookie has its value encrypted and authenticated. This prevents the
remote cookie owner from knowing what information is stored in the cookie or
modifying it. It also prevents an attacker from forging a fake cookie.
And since fake or altered cookie values are rejected in about 150 ns,
without any allocation, before any query to a session store, it mitigates
denial of service attacks flooding the server and its database with fake
cookies.

This package differs from the Gorilla secure cookie in that setting and
getting a cookie value are about 3 to 12 times faster, depending on the
platform and the operation, value decoding needs no heap allocation, and
encoded values are almost half as long. Values are encrypted and
authenticated with AES-128-GCM, with keys derived from a secret seed and
changed automatically every two days.

This is version 2 of the package. It is more secure, robust and faster than
version 1, and **users of version 1 are encouraged to upgrade**. See
[Migrating from v1](#migrating-from-v1). Version 1 is still available in the
[v1 branch](https://github.com/chmike/securecookie/tree/v1) and
[documented here](https://pkg.go.dev/github.com/chmike/securecookie).

**Note:** This package uses its own secure cookie value encoding. It is thus
incompatible with the Gorilla secure cookie package and the ones provided with
other language frameworks. This encoding is simpler and more efficient, and has
a version number to support evolution.

**Warning:** Because this package impacts security of web applications,
it is a critical functionality. Review feedbacks are always welcome.

If you enjoy the code and want to thank me 🙏, you can [buy me a coffee](https://www.buymeacoffee.com/Chmike).

## Content

- [Installation](#installation)
- [Usage](#usage)
- [Security](#security)
- [Migrating from v1](#migrating-from-v1)
- [Benchmarks](#benchmarks)
- [Qualitative comparison](#qualitative-comparison)
- [Value encoding](#value-encoding)
- [Contributors](#contributors)

## Installation

```bash
go get github.com/chmike/securecookie/v2
```

```go
import "github.com/chmike/securecookie/v2"
```

## Usage

**Secure cookies require HTTPS.** The cookies are always set with the
attribute `Secure`, so that user agents send them only over HTTPS. A server
behind a reverse proxy terminating TLS, like Caddy or nginx, can itself serve
HTTP to the proxy.

### Generating the seed

The keys are derived from a secret seed of `SeedLen` (32) bytes. Generate it
once, save it in a file readable only by the server, and load it at start up.
Servers sharing the same seed can decode the values encoded by the others.

```go
// loadSeed returns the seed saved in the file named name. A new seed is
// generated and saved if the file does not exist.
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
```

Don't store the seed in the source code or in a repository.

**Changing the seed invalidates all existing cookies:** their values can't be
decoded anymore, and users have to log in again.

**With several servers**, for instance with load balancing, all servers must
use the same seed, otherwise a server rejects the cookies set by the others.
Generate the seed once, and install a read-only copy of it on each server,
readable only by the server program. In this case, don't let each server
generate its own seed as `loadSeed` does above: a server started without the
seed file must fail instead.

### Instantiating the key store and the cookie objects

The intended use is to instantiate the key store and the cookie objects at
program start up. A key store may be shared by different cookie objects.

```go
keys, err := securecookie.NewKeyStore(seed)
if err != nil {
    // ...
}
// cookie named "__Host-session", with values valid two hours
session, err := securecookie.New("session", keys, 2*time.Hour)
if err != nil {
    // ...
}
```

`MustNewKeyStore` and `MustNew` panic instead of returning an error, which is
convenient to instantiate global variables.

```go
var keys = securecookie.MustNewKeyStore(seed)
var session = securecookie.MustNew("session", keys, 2*time.Hour)
```

`New` prefixes the cookie name with `__Host-`, and the cookie has the
attributes `Path=/`, `HttpOnly`, `Secure` and `SameSite=Lax`, without
`Domain`. The maximum age must be from one second to 400 days, the limit of
user agents. The `SameSite` attribute may be set to `Strict` with an option.

```go
admin, err := securecookie.New("admin", keys, 30*time.Minute,
    securecookie.WithSameSiteStrict())
```

### Setting a cookie value

```go
// with w as the http.ResponseWriter
if err := session.SetValue(w, val); err != nil {
    // ...
}
```

### Getting a cookie value

The value is appended to `buf`, which may be nil, and returned with the time
when it was set.

```go
// with r as the *http.Request
val, stamp, err := session.Value(buf, r)
if err != nil {
    // ...
}
```

`Value` returns `http.ErrNoCookie` when the request has no cookie with the
name, and `ErrMultipleCookies` when it has more than one, which doesn't
happen with user agents supporting the `__Host-` prefix, unless the request
was forged. On error, the returned value is nil.

### Deleting a cookie

```go
// with w as the http.ResponseWriter
if err := session.Delete(w); err != nil {
    // ...
}
```

**Note:** don't rely on the user agent to effectively delete the cookie. The
value stays valid until its maximum age, so session data must also be deleted
on the server.

### Complete example

A complete HTTPS server example is provided [here](example/main.go). Run it from
the repository root with `go run ./example`, and open `https://localhost:8443`
with your browser. The server uses a self-signed certificate for localhost, so
the browser warns that it is not trusted: accept the risk to continue.

## Security

### Store a random session id, not a user id

Store a random session id of 16 bytes in the cookie, and the session data,
like the user id, on the server, for instance in a database or Redis.

```go
var sid [16]byte
if _, err := rand.Read(sid[:]); err != nil { // crypto/rand
    // ...
}
if err := session.SetValue(w, sid[:]); err != nil {
    // ...
}
// store the session data with the key sha256.Sum256(sid[:])
```

The reasons are:

- **A leaked seed exposes nothing.** Anyone knowing the seed can decrypt
  captured cookies and forge values. A captured session id gives nothing more
  than the captured cookie itself, and a forged value holds a random session
  id unknown to the server. With a user id in the cookie, a leaked seed would
  allow impersonating any user.
- **Sessions can be revoked.** A cookie value stays valid until its maximum
  age. Deleting the session on the server, at logout, password change or user
  ban, invalidates it immediately. A user id can't be revoked.
- **Session ids can be changed.** Issue a new session id at login and when the
  user privileges change, to prevent session fixation. A user id never changes.
- **The session store is protected.** Values that are forged, altered or
  expired are rejected by this package in about 150 ns, before any query to
  the session store. Store the SHA-256 hash of the session id rather than the
  id itself, so that a leak of the session store gives no usable cookie.

### The `__Host-` prefix

User agents only accept a cookie with a name starting with `__Host-` when it
is set by the host itself over HTTPS, with `Secure`, `Path=/` and without
`Domain`. Another host, like a sibling subdomain, or a network attacker, can
then not set a cookie with the same name (cookie tossing). This prevents an
attacker from planting in the user agent a valid value obtained from his own
session.

### Keys

- Keep the seed secret, in a file readable only by the server. With several
  servers, each server has a read-only copy of the same seed.
- A new key is derived from the seed every two days, at midnight UTC, and the
  keys of the 200 previous periods are still accepted, which covers the
  maximum age of 400 days. Servers sharing the seed use the same keys without
  any synchronization.
- If the seed may have leaked, replace it on all servers. All existing cookies
  become invalid and users have to log in again.
- AES-GCM with random nonces is secure for up to 2³² values per key, that is
  about 24,800 encoded values per second on average with a key changed every
  two days.
- Disabling core dumps (`LimitCORE=0` with systemd) prevents the keys from
  being written to disk if the server crashes.

### Time

The value time stamp is checked strictly: a value is rejected after its
maximum age, and when its time stamp is in the future. Servers sharing a seed
must have synchronized clocks (NTP).

### Cross-site request forgery (CSRF)

Don't use cookies to protect forms against CSRF: cookies are shared by all the
tabs of a browser, so that forms opened in different tabs conflict. Instead:

- keep the default `SameSite=Lax`, so that the user agent doesn't send the
  cookie with cross-site POST requests;
- reject requests whose `Origin` or `Sec-Fetch-Site` header shows that they
  come from another site, which `http.CrossOriginProtection` of the standard
  library does;
- if a form needs a token, put it in a hidden field of the form, bound to the
  session id.

## Migrating from v1

### Why upgrade

- **Automatic key rotation.** The keys are derived from a seed and change
  every two days, without any synchronization between servers. With v1, the
  same key was used until it was changed manually, which invalidated all
  cookies.
- **Authenticated encryption.** Values are encrypted and authenticated with
  AES-128-GCM, a single standard construction, instead of AES-CTR and
  HMAC-SHA-256.
- **Secure defaults that can't be misconfigured.** The `__Host-` prefix,
  `Secure`, `HttpOnly`, `Path=/` and `SameSite=Lax` are always set, which
  prevents cookie tossing. A maximum age is required, so that a value never
  stays valid forever on the server side.
- **Detection of forged requests.** A request with several cookies of the
  same name is rejected.
- **Canonical encoding.** A value has a single valid encoding, and the
  decoder rejects any other one.
- **Faster and shorter.** Getting a value is up to 3 times faster than with
  v1 and needs no allocation, and encoded values are 28 characters shorter.

### How to upgrade

- Import `github.com/chmike/securecookie/v2`.
- Replace the key with a key store: `NewKeyStore(seed)`, with a seed generated
  by `GenerateSeed`. `KeyLen` and `GenerateRandomKey` are replaced by `SeedLen`
  and `GenerateSeed`.
- `New(name, keys, maxAge, options...)` replaces `New(name, key, Params{...})`.
  The maximum age is a `time.Duration`, from one second to 400 days. `Path`,
  `Domain`, `HTTPOnly` and `Secure` can't be set anymore, and `SameSite` is set
  with an option.
- The cookie name is prefixed with `__Host-`, so the v1 cookies are ignored.
- `Value(buf, r)` replaces `GetValue`, `GetValueAndStamp` and `GetValues`.
- HTTPS is required.
- The value encoding is not compatible with v1. Users have to log in again.

## Benchmarks

Median of 10 runs of `go test -run='^$' -bench=. -benchmem -count=10`, compared
with [Gorilla securecookie](https://github.com/gorilla/securecookie) v1.1.1, with
its default `gob` serializer and with `NopEncoder` (no serialization). Both use
16 byte keys, the same cookie name and attributes, and the same `Cookie` header
line. The value is "some value". The benchmark functions are at the bottom of
the file securecookie_test.go.

Linux amd64, AMD Ryzen AI 9 HX PRO 370, Go 1.27.3, run on a single core
(`taskset -c 0` and `-cpu=1`):

|               | Chmike | Gorilla NopEncoder | Gorilla gob |
| ------------: | -----: | -----------------: | ----------: |
|  Value length |     60 |                108 |         112 |
|     Set ns/op |    285 |  1301 (4.6× slower) | 1746 (6.1×) |
|     Get ns/op |    135 |   895 (6.6× slower) | 1624 (12×)  |
|      Set B/op |    208 |               1928 |        2808 |
|      Get B/op |      0 |               1552 |        2592 |
| Set allocs/op |      3 |                 21 |          33 |
| Get allocs/op |      0 |                 15 |          35 |

macOS arm64, Apple M2, Go 1.27.3:

|           | Chmike | Gorilla NopEncoder | Gorilla gob |
| --------: | -----: | -----------------: | ----------: |
| Set ns/op |    486 |  1320 (2.7× slower) | 1678 (3.5×) |
| Get ns/op |    153 |   846 (5.5× slower) | 1399 (9.2×) |

The value encoding is slower on macOS because reading random bytes for the
nonce is more expensive than on Linux.

Gorilla serializes values with `encoding/gob` by default, which accounts for a
large part of its time and allocations. Use `securecookie.NopEncoder{}` with
Gorilla to store `[]byte` values without serialization.

The 3 allocations of `SetValue` come from the `Set-Cookie` header string and
its addition to the `http.Header`. The value encoding and decoding need no
heap allocation.

## Qualitative comparison

Common to this package and the Gorilla secure cookie:

- The value is encrypted with AES-128, and authenticated.
- The cookie name is authenticated with the value, so that a value of a
  cookie can't be used as value of another cookie.
- A time stamp is added to the encoded value and checked against the
  maximum age.
- The value byte length is not concealed.

The differences are:

- This package uses AES-128-GCM, an authenticated encryption. Gorilla uses
  AES-128-CTR and HMAC-SHA-256 with two keys.
- This package derives its keys from a seed and changes them every two days,
  without key synchronization between servers. Gorilla uses fixed keys, with
  optional decoding with previous keys.
- This package is faster, needs fewer allocations, and its encoded values are
  shorter.
- This package enforces the `__Host-` prefix, HTTPS, and rejects requests
  with multiple cookies of the same name.
- The encoding has a version number allowing to change the encoding.
- This package provides a `Delete` method.
- The encodings are incompatible.

## Value encoding

The encoded value is the base64 URL encoding
([RFC 4648](https://tools.ietf.org/html/rfc4648#section-5)), without padding,
of:

    [header][nonce][AES-128-GCM(stamp ‖ value ‖ padding)][GCM tag]

- The header is 2 bytes:
    - the 6 most significant bits of the first byte are the encoding version,
    currently 1 (version 0 was used by v1), and its 2 least significant bits
    are the number of padding bytes;
    - the second byte is the key id, the least significant byte of the key
    period index (unix time / 172800).
- The nonce is 12 cryptographically secure pseudorandom bytes.
- The stamp is the unix time minus 1505230500, encoded with
  [LEB128](https://en.wikipedia.org/wiki/LEB128).
- The value is a copy of the user provided value.
- The padding is 0 to 2 zero bytes, so that the total length is a multiple
  of 3 bytes, which avoids the base64 padding. The decoder checks that the
  padding bytes are zeros, so that the encoding is canonical.
- The GCM tag is 16 bytes.
- The cookie name and the header are the additional authenticated data: they
  are not encrypted, but authenticated.

The key of a period is derived from the seed with HKDF-SHA256
([RFC 5869](https://tools.ietf.org/html/rfc5869)), with a zero salt, the seed
as input key material, and as info the string "securecookie v2 key" followed
by the period index as a big endian 64 bit integer. The key is the first 16
bytes of the output.

## Contributors

- lstokeworth (reddit):
    - suggest to replace `copy` with `append`,
    - remove the Expires Params field and use only the MaxAge,
    - provide a constant date in the past for Delete.
- cstockton (github):
    - critical [bug report](https://github.com/chmike/cookie/issues/1),
    - suggest simpler API.
- flowonyx (github):
    - fix many typos in the README and comments.
- Claude Opus 5.5 (Anthropic):
    - assisted with the security review of v1.4 and the design and
    implementation of v2.
