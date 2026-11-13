// Deprecated: use github.com/chmike/securecookie/v2, which is more secure,
// with automatic key rotation, authenticated encryption and secure defaults.
module github.com/chmike/securecookie

// used for benchmarking only
require github.com/gorilla/securecookie v1.1.1

go 1.16

retract [v0.1.0, v1.3.1] // due to various bug fix
