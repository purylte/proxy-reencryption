//! This is the main entry point of the proxy re-encryption CLI.
//!
//! It uses the `clap` crate to parse command line arguments and provides three subcommands: `encrypt`, `decrypt`, and `reencrypt`.

use clap::{arg, Command};
use proxy_reencryption_lib::proxy_reencryption_lib::{Blocks, Key, ProxyReencryption};
use std::fs::File;
use std::io::{self, Read, Write};

fn main() -> std::io::Result<()> {
    let app = Command::new("Symmetric Proxy Re-encryption CLI")
        .version("1.0")
        .about("Implementation of proxy re-encryption scheme for symmetric key cryptography in 10.1109/IWBIS.2017.8275110")
        .subcommand(
            Command::new("encrypt")
                .about("Encrypts the file")
                .arg(arg!(-k --"keys-path" <FILE> "Path to the keys file").required(true))
                .arg(arg!(-c --"counter" <INTEGER> "Counter value for encryption").required(true))
                .arg(arg!(-p --"plaintext-path" <FILE> "Path to the plaintext file").required(true))
                .arg(arg!(-v --"iv-output-path" <FILE> "Path to save the IV output").required(true))
                .arg(
                    arg!(-t --"ciphertext-output-path" <FILE> "Path to save the encrypted data")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts the file")
                .arg(arg!(-k --"keys-path" <FILE> "Path to the keys file").required(true))
                .arg(arg!(-c --"counter" <INTEGER> "Counter value for decryption").required(true))
                .arg(arg!(-v --"iv-input-path" <FILE> "Path to the IV file").required(true))
                .arg(
                    arg!(-t --"ciphertext-input-path" <FILE> "Path to the encrypted data file")
                        .required(true),
                )
                .arg(
                    arg!(-p --"plaintext-output-path" <FILE> "Path to save the decrypted data")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("reencrypt")
                .about("Re-encrypts the file")
                .arg(arg!(-k --"keys-path" <FILE> "Path to the keys file").required(true))
                .arg(
                    arg!(-t --"ciphertext-input-path" <FILE> "Path to the encrypted data file")
                        .required(true),
                )
                .arg(arg!(-v --"iv-input-path" <FILE> "Path to the IV file").required(true))
                .arg(
                    arg!(-r --"reencrypted-output-path" <FILE> "Path to save the reencrypted data")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("generate-key")
                .about("Generate re-encryption key and decryption key")
                .arg(arg!(-k --"keys-path" <FILE> "Path to the keys file").required(true))
                .arg(arg!(-p --"plaintext-path" <FILE> "Path to the plaintext file").required(true))
                .arg(
                    arg!(-r --"reencryption-keys-output-path" <FILE> "Path to save the reencryption keys")
                        .required(true),
                )
                .arg(
                    arg!(-d --"decryption-keys-output-path" <FILE> "Path to save the decryption keys")
                        .required(true),
                )
        )
        .get_matches();

    match app.subcommand() {
        Some(("encrypt", sub_m)) => encrypt(
            sub_m.get_one::<String>("keys-path").unwrap(),
            sub_m
                .get_one::<String>("counter")
                .unwrap()
                .parse::<u64>()
                .expect("Counter should be an integer"),
            sub_m.get_one::<String>("plaintext-path").unwrap(),
            sub_m.get_one::<String>("iv-output-path").unwrap(),
            sub_m.get_one::<String>("ciphertext-output-path").unwrap(),
        ),
        Some(("decrypt", sub_m)) => decrypt(
            sub_m.get_one::<String>("keys-path").unwrap(),
            sub_m
                .get_one::<String>("counter")
                .unwrap()
                .parse::<u64>()
                .expect("Counter should be an integer"),
            sub_m.get_one::<String>("iv-input-path").unwrap(),
            sub_m.get_one::<String>("ciphertext-input-path").unwrap(),
            sub_m.get_one::<String>("plaintext-output-path").unwrap(),
        ),
        Some(("reencrypt", sub_m)) => reencrypt(
            sub_m.get_one::<String>("keys-path").unwrap(),
            sub_m.get_one::<String>("ciphertext-input-path").unwrap(),
            sub_m.get_one::<String>("iv-input-path").unwrap(),
            sub_m.get_one::<String>("reencrypted-output-path").unwrap(),
        ),
        Some(("generate-key", sub_m)) => generate_reencrypt_key(
            sub_m.get_one::<String>("keys-path").unwrap(),
            sub_m.get_one::<String>("plaintext-path").unwrap(),
            sub_m
                .get_one::<String>("reencryption-keys-output-path")
                .unwrap(),
            sub_m
                .get_one::<String>("decryption-keys-output-path")
                .unwrap(),
        ),
        _ => {
            eprintln!("Invalid command or missing arguments");
            Ok(())
        }
    }
}

fn generate_reencrypt_key(
    keys_path: &str,
    plaintext_path: &str,
    reencrypt_key_path: &str,
    decrypt_key_path: &str,
) -> Result<(), io::Error> {
    let keys = IOHelper::read_file_to_vec(keys_path).expect("Failed to read keys");
    assert_eq!(keys.len(), 48, "Key have to 48 bytes");
    let k1 = Key::from_vec(keys[0..16].try_into().expect("Invalid key format"));
    let k2 = Key::from_vec(keys[16..32].try_into().expect("Invalid key format"));
    let k3 = Key::from_vec(keys[32..48].try_into().expect("Invalid key format"));
    let n = Blocks::from_vec(
        IOHelper::read_file_to_vec(plaintext_path).expect("Failed to read plaintext"),
    )
    .blocks
    .len();
    let (ck1, k2, k2_1, ck3, k1_1, k3_1) =
        ProxyReencryption::reencryption_key_generator(&k1, &k2, &k3, n);

    IOHelper::write_vec_usize_to_file(
        &IOHelper::concat_reencrypt_keys(ck1, &k2, &k2_1, ck3),
        reencrypt_key_path,
    )
    .expect("Failed to write re-encryption key");
    IOHelper::write_slice_to_file(&[k1_1.key, k2_1.key, k3_1.key].concat(), decrypt_key_path)
        .expect("Failed to write decryption key");

    Ok(())
}

fn reencrypt(
    keys_path: &str,
    ciphertext_path: &str,
    iv_path: &str,
    ciphertext_reencrypted_path: &str,
) -> Result<(), io::Error> {
    let keys = IOHelper::read_vec_usize_from_file(keys_path).expect("Failed to read keys");
    let (ck1, k2, k2_1, ck3) = IOHelper::split_reencrypt_keys::<16>(keys);
    let ciphertext = Blocks::from_vec_no_pad(
        IOHelper::read_file_to_vec(ciphertext_path).expect("Failed to read ciphertext"),
    );
    let iv = IOHelper::read_file_to_vec(iv_path)
        .expect("Failed to read IV")
        .as_slice()
        .try_into()
        .expect("IV have to be 16 bytes");

    let (_, ciphertext_re) = ProxyReencryption::reencryption(ck1, &k2, &k2_1, ck3, &iv, ciphertext);

    IOHelper::write_vec_to_file(&ciphertext_re.blocks, ciphertext_reencrypted_path)
        .expect("Failed to write new ciphertext");
    Ok(())
}

fn decrypt(
    keys_path: &str,
    ctr: u64,
    iv_path: &str,
    ciphertext_path: &str,
    plaintext_path: &str,
) -> Result<(), io::Error> {
    let keys = IOHelper::read_file_to_vec(keys_path).expect("Failed to read keys");
    assert_eq!(keys.len(), 48, "Key have to 48 bytes");
    let k1_1 = Key::from_vec(keys[0..16].try_into().expect("Invalid key format"));
    let k2_1 = Key::from_vec(keys[16..32].try_into().expect("Invalid key format"));
    let k3_1 = Key::from_vec(keys[32..48].try_into().expect("Invalid key format"));
    let ciphertext_re = Blocks::from_vec_no_pad(
        IOHelper::read_file_to_vec(ciphertext_path).expect("Failed to read ciphertext"),
    );
    let iv = IOHelper::read_file_to_vec(iv_path)
        .expect("Failed to read IV")
        .as_slice()
        .try_into()
        .expect("IV have to be 16 bytes");
    let ctr = ctr;
    let decrypted = ProxyReencryption::decryption(&k1_1, &k2_1, &k3_1, ctr, &iv, ciphertext_re);

    IOHelper::write_slice_to_file(&decrypted.remove_padding()?, plaintext_path)
        .expect("Failed to write plaintext");
    Ok(())
}

fn encrypt(
    keys_path: &str,
    ctr: u64,
    plaintext_path: &str,
    iv_path: &str,
    ciphertext_path: &str,
) -> Result<(), io::Error> {
    let plaintext = Blocks::from_vec(
        IOHelper::read_file_to_vec(plaintext_path).expect("Failed to read plaintext"),
    );

    let keys = IOHelper::read_file_to_vec(keys_path).expect("Failed to read keys");
    assert_eq!(keys.len(), 48, "Key have to 48 bytes");
    let k1 = Key::from_vec(keys[0..16].try_into().expect("Invalid key format"));
    let k2 = Key::from_vec(keys[16..32].try_into().expect("Invalid key format"));
    let k3 = Key::from_vec(keys[32..48].try_into().expect("Invalid key format"));

    let ctr = ctr;

    let (iv, c) = ProxyReencryption::encryption(&k1, &k2, &k3, ctr, &plaintext);

    IOHelper::write_slice_to_file(&iv, iv_path).expect("Failed to write IV");

    IOHelper::write_vec_to_file(&c.blocks, ciphertext_path).expect("Failed to write ciphertext");
    Ok(())
}

struct IOHelper;

impl IOHelper {
    fn write_slice_to_file(data: &[u8], file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?;
        file.write_all(data)?;
        Ok(())
    }

    fn write_vec_to_file(data: &Vec<[u8; 16]>, file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?;
        for slice in data {
            file.write_all(slice)?;
        }
        Ok(())
    }

    fn read_file_to_vec(file_path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    fn concat_reencrypt_keys<const N: usize>(
        ck1: Vec<usize>,
        k2: &Key<N>,
        k2_1: &Key<N>,
        ck3: Vec<usize>,
    ) -> Vec<usize> {
        let mut result: Vec<usize> = ck1.clone();
        result.extend(k2.key.into_iter().map(|x| x as usize));
        result.extend(k2_1.key.into_iter().map(|x| x as usize));
        result.extend(ck3.clone());
        result
    }

    fn write_vec_usize_to_file(vec: &Vec<usize>, file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?;
        for &num in vec {
            let bytes = num.to_le_bytes();
            file.write_all(&bytes)?;
        }
        Ok(())
    }

    fn read_vec_usize_from_file(file_path: &str) -> io::Result<Vec<usize>> {
        let mut file = File::open(file_path)?;
        let mut vec = Vec::new();
        let mut bytes = [0; 8];
        while let Ok(n) = file.read(&mut bytes) {
            if n == 0 {
                break;
            }
            let num = usize::from_le_bytes(bytes);
            vec.push(num);
        }
        Ok(vec)
    }

    fn split_reencrypt_keys<const N: usize>(
        concatenated: Vec<usize>,
    ) -> (Vec<usize>, Key<N>, Key<N>, Vec<usize>) {
        let ck1_len = N;
        let k2_len = N;
        let k2_1_len = N;

        let (ck1, rest) = concatenated.split_at(ck1_len);
        let ck1: Vec<usize> = ck1.to_vec();

        let (k2, rest) = rest.split_at(k2_len);
        let k2: Vec<usize> = k2.to_vec();
        let k2: Vec<u8> = k2.into_iter().map(|x| x as u8).collect();
        let k2: [u8; N] = k2.try_into().unwrap();

        let (k2_1, ck3) = rest.split_at(k2_1_len);
        let k2_1: Vec<usize> = k2_1.to_vec();
        let k2_1: Vec<u8> = k2_1.into_iter().map(|x| x as u8).collect();
        let k2_1: [u8; N] = k2_1.try_into().unwrap();

        let ck3: Vec<usize> = ck3.to_vec();

        (ck1, Key::new(k2), Key::new(k2_1), ck3)
    }
}
