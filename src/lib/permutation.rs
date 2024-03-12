pub fn permutation<T: Clone>(p: &Vec<usize>, x: &Vec<T>) -> Vec<T> {
    let mut result = x.clone();
    for i in 0..p.len() {
        result.swap(i, p[i]);
    }
    result
}

pub fn depermutation<T: Clone>(p: &Vec<usize>, x: &Vec<T>) -> Vec<T> {
    let mut result = x.clone();
    for i in 0..p.len() {
        result.swap(p[i], i);
    }
    result
}

pub fn find_conversion_key<const N: usize>(pa: &[u8; N], pb: &[u8; N]) -> [u8; N] {
    let mut pc = [0; N];
    for i in 0..N {
        for j in 0..N {
            if pa[i] == pb[j] {
                pc[j] = i as u8;
                break;
            }
        }
    }
    pc
}
