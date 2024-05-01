use crate::{
    proxy_reencryption_lib::Key,
    utils::{encrypt, new_random_arr},
};

pub fn key_generator_with_keys(
    k1: &Key<16>,
    k2: &Key<16>,
    k3: &Key<16>,
    n: usize,
) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    let p1 = pg(k1, 16);
    let p2 = pg(k2, 16);
    let p3 = pg(k3, n);

    (p1, p2, p3)
}

pub fn key_generator(
    n: usize,
) -> (
    Vec<usize>,
    Vec<usize>,
    Vec<usize>,
    Key<16>,
    Key<16>,
    Key<16>,
) {
    let t_k1 = Key::new(new_random_arr::<16>());
    let t_k2 = Key::new(new_random_arr::<16>());
    let t_k3 = Key::new(new_random_arr::<16>());

    let p1 = pg(&t_k1, 16);
    let p2 = pg(&t_k2, 16);
    let p3 = pg(&t_k3, n);

    (p1, p2, p3, t_k1, t_k2, t_k3)
}

pub fn pg(key: &Key<16>, n: usize) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).collect();
    let tmp: Vec<[u8; 16]> = (0..n).map(|i| encrypt(i as u128, &key.key)).collect();
    p.sort_unstable_by_key(|&x| tmp[(x) as usize]);
    p
}

#[cfg(test)]
mod aonth_tests {
    use crate::{key_generator::pg, proxy_reencryption_lib::Key};

    #[test]
    fn pg_1_test() {
        let key = Key::new([1; 16]);
        println!("{:?}", pg(&key, 20));
    }
}
