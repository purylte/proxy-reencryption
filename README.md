# Symmetric Proxy Re-encryption CLI
Implementation of proxy re-encryption scheme for symmetric key cryptography defined in 10.1109/IWBIS.2017.8275110

## Example usage
To see the available commands and options, run:
`./proxy_reencryption -help`

To create new key use `openssl rand -out <FILE> 48`
### Encryption
```
./proxy_reencryption encrypt \
  --keys-path "./example/keys.key" \
  --counter 10 \
  --plaintext-path "./example/plaintext" \
  --iv-output-path "./example/iv" \
  --ciphertext-output-path "./example/ciphertext"
```

### Generate Re-encryption Key
```
./proxy_reencryption generate-key \
  --keys-path "./example/keys.key" \
  --plaintext-path "./example/plaintext" \
  --reencryption-keys-output-path "./example/reencrypt_keys.key" \
  --decryption-keys-output-path "./example/decrypt_keys.key"
```

### Re-encryption
```
./proxy_reencryption reencrypt \
  --keys-path "./example/reencrypt_keys.key" \
  --ciphertext-input-path "./example/ciphertext" \
  --iv-input-path "./example/iv" \
  --reencrypted-output-path "./example/reencrypted"
```
### Decryption
```
./proxy_reencryption decrypt \
  --keys-path "./example/decrypt_keys.key" \
  --counter 10 \
  --iv-input-path "./example/iv" \
  --ciphertext-input-path "./example/reencrypted" \
  --plaintext-output-path "./example/new_plaintext"
```

### Benchmark
```
cargo bench --- benchmark_pre
cargo bench --- benchmark_aes
```

## Library Documentation
The documentation of proxy re-encryption library can be found [here](https://purylte.github.io/proxy-reencryption/proxy_reencryption_lib/index.html) 

## License

- [MIT License - purylte/proxy-reencryption]

[MIT License - purylte/proxy-reencryption]: https://github.com/purylte/proxy-reencryption/blob/master/LICENSE

