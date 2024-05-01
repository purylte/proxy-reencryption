use clap::{arg, Command};
use proxy_reencryption_lib::proxy_reencryption_lib::{Blocks, Key, ProxyReencryption};
use std::fs::File;
use std::io::{self, Read, Write};

fn main() -> std::io::Result<()> {
    let app = Command::new("Proxy Re-encryption CLI")
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
                    arg!(-n --"new-keys-output-path" <FILE> "Path to save the new keys")
                        .required(true),
                )
                .arg(
                    arg!(-r --"reencrypted-output-path" <FILE> "Path to save the reencrypted data")
                        .required(true),
                ),
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
            sub_m.get_one::<String>("new-keys-output-path").unwrap(),
            sub_m.get_one::<String>("reencrypted-output-path").unwrap(),
        ),
        _ => {
            eprintln!("Invalid command or missing arguments");
            Ok(())
        }
    }
}

fn reencrypt(
    keys_path: &str,
    ciphertext_path: &str,
    iv_path: &str,
    keys_new_path: &str,
    ciphertext_reencrypted_path: &str,
) -> Result<(), io::Error> {
    let keys = IOHelper::read_file_to_vec(keys_path)?;
    assert_eq!(keys.len(), 48, "Key have to 48 bytes");
    let k1 = Key::from_vec(keys[0..16].try_into().expect("Invalid key format"));
    let k2 = Key::from_vec(keys[16..32].try_into().expect("Invalid key format"));
    let k3 = Key::from_vec(keys[32..48].try_into().expect("Invalid key format"));
    let ciphertext = Blocks::from_vec_no_pad(IOHelper::read_file_to_vec(ciphertext_path)?);
    let iv = IOHelper::read_file_to_vec(iv_path)?
        .as_slice()
        .try_into()
        .expect("IV have to be 16 bytes");
    let (ck1, k2, k2_1, ck3, k1_1, k3_1) =
        ProxyReencryption::reencryption_key_generator(&k1, &k2, &k3, ciphertext.blocks.len() - 1);

    let (_, ciphertext_re) = ProxyReencryption::reencryption(ck1, &k2, &k2_1, ck3, &iv, ciphertext);

    IOHelper::write_slice_to_file(&[k1_1.key, k2_1.key, k3_1.key].concat(), keys_new_path)?;

    IOHelper::write_vec_to_file(&ciphertext_re.blocks, ciphertext_reencrypted_path)?;
    Ok(())
}

fn decrypt(
    keys_path: &str,
    ctr: u64,
    iv_path: &str,
    ciphertext_path: &str,
    plaintext_path: &str,
) -> Result<(), io::Error> {
    let keys = IOHelper::read_file_to_vec(keys_path)?;
    assert_eq!(keys.len(), 48, "Key have to 48 bytes");
    let k1_1 = Key::from_vec(keys[0..16].try_into().expect("Invalid key format"));
    let k2_1 = Key::from_vec(keys[16..32].try_into().expect("Invalid key format"));
    let k3_1 = Key::from_vec(keys[32..48].try_into().expect("Invalid key format"));
    let ciphertext_re = Blocks::from_vec_no_pad(IOHelper::read_file_to_vec(ciphertext_path)?);
    let iv = IOHelper::read_file_to_vec(iv_path)?
        .as_slice()
        .try_into()
        .expect("IV have to be 16 bytes");
    let ctr = ctr;
    let decrypted = ProxyReencryption::decryption(&k1_1, &k2_1, &k3_1, ctr, &iv, ciphertext_re);

    IOHelper::write_slice_to_file(&decrypted.remove_padding()?, plaintext_path)
}

fn encrypt(
    keys_path: &str,
    ctr: u64,
    plaintext_path: &str,
    iv_path: &str,
    ciphertext_path: &str,
) -> Result<(), io::Error> {
    let plaintext = Blocks::from_vec(IOHelper::read_file_to_vec(plaintext_path)?);

    let keys = IOHelper::read_file_to_vec(keys_path)?;
    assert_eq!(keys.len(), 48, "Key have to 48 bytes");
    let k1 = Key::from_vec(keys[0..16].try_into().expect("Invalid key format"));
    let k2 = Key::from_vec(keys[16..32].try_into().expect("Invalid key format"));
    let k3 = Key::from_vec(keys[32..48].try_into().expect("Invalid key format"));

    let ctr = ctr;

    let (iv, c) = ProxyReencryption::encryption(&k1, &k2, &k3, ctr, &plaintext);

    IOHelper::write_slice_to_file(&iv, iv_path)?;

    IOHelper::write_vec_to_file(&c.blocks, ciphertext_path)?;
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
}
