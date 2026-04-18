# Lokto_xchacha20

A XChaCha20-Poly1305 implementation built on top of mirage-crypto.

## Usage

In dune-project:

```dune
(package
  (depends
    ...
    lokto_xchacha20)

(pin
  (url "git+https://github.com/itswindtw/lokto_xchacha20")
  (package
    (name lokto_xchacha20)))
```

In code:

```ocaml
let ciphertext = Lokto_xchacha20.authenticate_encrypt ~key ~nonce ~aad plaintext in
...
```
