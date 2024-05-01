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

    let (iv, c) = ProxyReencryption::encryption(&k1, &k2, &k3, ctr, &plaintext);

    let (ck1, k2, k2_1, ck3, k1_1, k3_1) =
        ProxyReencryption::reencryption_key_generator(&k1, &k2, &k3, plaintext.blocks.len());

    let (_, c_re) = ProxyReencryption::reencryption(ck1, &k2, &k2_1, ck3, &iv, c);

    let decrypted = ProxyReencryption::decryption(&k1_1, &k2_1, &k3_1, ctr, &iv, c_re);

    println!("{:?}", plaintext.blocks);
    println!("{:?}", decrypted.blocks);

    IOHelper::write_slice_to_file(
        &decrypted.remove_padding()?,
        "/workspaces/proxy-reencryption/example/new_plaintext",
    )
}

struct IOHelper;

impl IOHelper {
    fn write_slice_to_file(data: &[u8], file_path: &str) -> io::Result<()> {
        let mut file = File::create(file_path)?;
        file.write_all(data)?;
        Ok(())
    }

    fn read_file_to_vec(file_path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}
