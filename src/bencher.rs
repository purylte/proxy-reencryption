use proxy_reencryption_lib::proxy_reencryption_lib::{Blocks, Key, ProxyReencryption};

fn main() {
    use std::time::Instant;

    let k1 = Key::new([0; 16]);
    let k2 = Key::new([0; 16]);
    let k3 = Key::new([0; 16]);
    let ctr: u8 = 0;
    let m = Blocks::new(vec![[0; 16]; 10000]);

    let now = Instant::now();

    {
        // for _ in 0..1000 {
        ProxyReencryption::encryption(&k1, &k2, &k3, ctr, &m);
        // }
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {} ns", elapsed.as_nanos());
}
