# JWT CLI
Simple cli wrapper around [jsonwetoken](https://docs.rs/jsonwebtoken).

This app just reads a jwt stream from stdin, validates, and writes the 
payload to stdout.  That's it.

If a key is provided, the memory is cleared with [RustCrypto Zeroize](https::/docs.rs/zeroize)  before the program exists.

# Validation
By default, only the signature is validated.  No header validation is done. 
You can use the --validate option to add a list of headers you would like to validate.

# ToDo

## JWE
Currently, encryption/decryption is not supported.  Just signed JWTs

## More signing algs
Currently only an embedded `x5c` claim is used for validating.  Keys are accepted on the command line, but not yet used.