use proxy_reencryption_lib::reencryption::{decryption, encryption};

fn main() {
    // let mut file = File::open("/workspaces/proxy-reencryption/example/plaintext.txt")?;

    // let mut buffer = Vec::new();
    // file.read_to_end(&mut buffer)?;

    // let chunks: Vec<[u8; 16]> = buffer
    //     .chunks_exact(16)
    //     .map(|chunk| {
    //         let mut arr: [u8; 16] = Default::default();
    //         arr.copy_from_slice(chunk);
    //         arr
    //     })
    //     .collect();

    // println!("{:#?}", chunks);

    let k1 = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let k2 = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let k3 = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let ctr = 5;
    let m = vec![
        [
            122, 121, 233, 41, 213, 162, 222, 34, 12, 31, 2, 131, 241, 136, 242, 123,
        ],
        [
            3, 240, 238, 236, 123, 27, 18, 219, 182, 3, 61, 37, 47, 153, 104, 37,
        ],
        [
            244, 189, 162, 112, 38, 189, 169, 223, 43, 169, 252, 33, 229, 26, 197, 41,
        ],
        [
            166, 151, 86, 20, 73, 50, 189, 91, 163, 72, 98, 186, 136, 97, 160, 10,
        ],
    ];

    let (iv, c) = encryption(k1, k2, k3, ctr, &m);
    let m_1 = decryption(k1, k2, k3, ctr, &iv, &c);
    assert_eq!(m, m_1);
}
