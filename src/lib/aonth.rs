use crate::utils::{encrypt, hash, new_random_arr, xor};

pub fn e_aonth(ctr: u8, m: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m.len();
    let k_1 = new_random_arr::<16>();

    let mut x: Vec<[u8; 16]> = vec![[0; 16]; n];
    for i in 0..n {
        x[i] = xor(&m[i], &encrypt(ctr + i as u8, &k_1));
    }

    let mut m_1 = vec![[0; 16]; n + 1];
    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    m_1[n] = xor(&k_1, &hash(&x_alloc));

    let mut ctr_bytes = [0u8; 16];
    for i in 0..n {
        ctr_bytes[15] = ctr + i as u8;
        m_1[i] = xor(&x[i], &hash(&xor(&m_1[n], &ctr_bytes)))
    }

    m_1
}

pub fn d_aonth(ctr: u8, m_1: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {
    let n = m_1.len() - 1;
    let mut x = vec![[0; 16]; n];
    let mut ctr_bytes = [0u8; 16];

    for i in 0..n {
        ctr_bytes[15] = ctr + i as u8;
        x[i] = xor(&m_1[i], &hash(&xor(&m_1[n], &ctr_bytes)))
    }

    let x_alloc: Vec<u8> = x.iter().flatten().cloned().collect();
    let k_1 = xor(&m_1[n], &hash(&x_alloc));

    let mut m = vec![[0; 16]; n];
    for i in 0..n {
        m[i] = xor(&x[i], &encrypt(ctr + i as u8, &k_1));
    }

    m
}

#[cfg(test)]
mod aonth_tests {
    use crate::aonth::{d_aonth, e_aonth};

    #[test]
    fn symmetric_tests() {
        let m = vec![
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [
                254, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
            ],
        ];
        let e = e_aonth(10, &m);
        assert_eq!(d_aonth(10, &e), m);
    }

    #[test]
    fn e_aonth_correctness() {
        let m = vec![[
            128, 0, 0, 0, 0, 0, 0, 0, 127, 255, 255, 255, 255, 255, 255, 255,
        ]];
        let e = e_aonth(10, &m);
        let expected = vec![
            [
                135, 32, 7, 22, 184, 102, 26, 4, 51, 37, 239, 163, 144, 68, 109, 203,
            ],
            [
                172, 249, 67, 199, 102, 178, 107, 211, 62, 173, 252, 30, 255, 44, 202, 125,
            ],
        ];
        assert_eq!(e, expected);
    }
}
