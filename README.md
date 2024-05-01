# Proxy Re-encryption CLI
Implementation of proxy re-encryption scheme for symmetric key cryptography defined in 10.1109/IWBIS.2017.8275110

## Example usage
`cargo run -- -help`

### Encryption
```
cargo run -- encrypt \
  --keys-path "./example/keys" \
  --counter 10 \
  --plaintext-path "./example/plaintext" \
  --iv-output-path "./example/iv" \
  --ciphertext-output-path "./example/ciphertext"
```

### Re-encryption
```
cargo run -- reencrypt \
  --keys-path "./example/keys" \
  --ciphertext-input-path "./example/ciphertext" \
  --iv-input-path "./example/iv" \
  --new-keys-output-path "./example/keys_new" \
  --reencrypted-output-path "./example/reencrypted"
```
### Decryption
```
cargo run -- decrypt \
  --keys-path "./example/keys_new" \
  --counter 10 \
  --iv-input-path "./example/iv" \
  --ciphertext-input-path "./example/reencrypted" \
  --plaintext-output-path "./example/new_plaintext"
```