use std::fs::File;
use std::io::{self, Read, Write};

use proxy_reencryption_lib::proxy_reencryption_lib::{Blocks, Key, ProxyReencryption};

fn main() -> io::Result<()> {
    let plaintext = Blocks::from_vec(IOHelper::read_file_to_vec(
        "/workspaces/proxy-reencryption/example/plaintext",
    )?);

    let k1 = Key::from_vec(IOHelper::read_file_to_vec(
        "/workspaces/proxy-reencryption/example/key1",
    )?);
    let k2 = Key::from_vec(IOHelper::read_file_to_vec(
        "/workspaces/proxy-reencryption/example/key2",
    )?);
    let k3 = Key::from_vec(IOHelper::read_file_to_vec(
        "/workspaces/proxy-reencryption/example/key3",
    )?);

    let ctr = 10;

    let (iv, c) = ProxyReencryption::encryption(&k1, &k2, &k3, ctr, plaintext);
    let decrypted = ProxyReencryption::decryption(&k1, &k2, &k3, ctr, &iv, c).remove_padding()?;

    IOHelper::write_slice_to_file(
        &decrypted,
        "/workspaces/proxy-reencryption/example/new_ciphertext",
    )
}

struct IOHelper;

impl IOHelper {
    fn print_slice(data: &[u8]) {
        for byte in data {
            print!("{:08b} ", byte);
        }
        println!();
    }

    fn print_vec(data: &Vec<[u8; 16]>) {
        for slice in data {
            for byte in slice {
                print!("{:08b} ", byte);
            }
            println!();
        }
    }

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
