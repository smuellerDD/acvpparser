v0.6.1
- addition of RSADP for OpenSSL
- add first bits of ECDSA primitive testing
- add HKDF and Curve25519 internal testing

v0.6.0
- remove requirement for mct_get_last_iv
- PBKDF: data->password.len now truly contains the correct length of the password
- add RSA signature primitive and decryption primitive support
- ACVP server sample files can be used in regression testing (-e option)
- fix: Invoke RSA_generate_key_ex multiple times if one invocation fails
- add private version of HKDF protocol
- add private version of ED-ECDH
- fixes for -Wconversion and -Wdocumentation

v0.5.3
- reenable OpenSSL FIPS mode
- add new TLS KDF and SSH KDF implementations to OpenSSL
- add OpenSSL 1.0.x support
- add AES GMAC support
- rename test case references from Common to "Generic C" to be compliant with
  ACVP Proxy

v0.5.2
- add PBKDF2 support for OpenSSL

v0.5.1
- OpenSSL add support for upstream CTR DRBG
- Add support for AES-CBC-CS*
- add color-coded logging
- fix some documentation

v0.5.0
- Add SHAKE support for OpenSSL
- Add Ubuntu-specific OpenSSL handling
- ACVP v1.0 support

v0.4.4:
- Compile ACVP parser tool with -m32 for 32 bit testing
- Fix DSA siggen helper to generate PQG and DSA key at the same time
- constify data in parser_common.c

v0.4.3
- OpenSSL: enable SHA3/HMAC SHA3

Changes 0.4.2
- add helper convert_cipher_algo
- use specific initializations for static variables (some compilers cannot handle generic initializations)
- statically link JSON-C

Changes 0.4.1
 * Addition of helper function to turn an MPI into a byte array

Changes 0.4.0
 * First public release with support for ACVP v0.5
