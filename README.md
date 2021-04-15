# AutoHttps
A simplified wrapper for net/http for when you just
need a quick and dirty https server.

It automatically generates a TLS cert/key pair for each run, 
starts the server, and deletes the key for each instantiation.

No more pointing to snakeoil or having to lookup openssl commands.

Cert/key generation is based off of https://golang.org/src/crypto/tls/generate_cert.go
