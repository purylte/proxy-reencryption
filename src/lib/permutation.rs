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

pub fn find_conversion_key(pa: &Vec<usize>, pb: &Vec<usize>) -> Vec<usize> {
    let n = pa.len();
    let mut pc = Vec::with_capacity(n);
    for i in 0..n {
        for j in 0..n {
            if pa[i] == pb[j] {
                pc[j] = i;
                break;
            }
        }
    }
    pc
}
