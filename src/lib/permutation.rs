pub fn permutate_vec<T: Clone + Copy>(p: &Vec<usize>, x: &Vec<T>) -> Vec<T> {
    let mut result = Vec::with_capacity(p.len());
    for i in 0..p.len() {
        result.push(x[p[i]]);
    }
    result
}

pub fn depermutate_vec<T: Clone + Copy>(p: &Vec<usize>, x: &Vec<T>) -> Vec<T> {
    let mut result = vec![x[0]; p.len()];
    for i in 0..p.len() {
        result[p[i]] = x[i];
    }
    result
}

pub fn permutate<T: Clone + Copy, const N: usize>(p: &Vec<usize>, x: &[T; N]) -> [T; N] {
    let mut result = [x[0].clone(); N];
    for i in 0..p.len() {
        result[i] = x[p[i]];
    }
    result
}

pub fn depermutate<T: Clone + Copy, const N: usize>(p: &Vec<usize>, x: &[T; N]) -> [T; N] {
    let mut result = [x[0].clone(); N];
    for i in 0..p.len() {
        result[p[i]] = x[i];
    }
    result
}

pub fn find_conversion_key(pa: &Vec<usize>, pb: &Vec<usize>) -> Vec<usize> {
    let n = pa.len();
    let mut pc = vec![0; n];
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

#[cfg(test)]
mod permutation_tests {
    use crate::permutation::{depermutate, depermutate_vec, permutate, permutate_vec};

    #[test]
    fn correctness_check() {
        assert_eq!(permutate(&vec!(1, 0, 3, 2), &[1, 2, 3, 4]), [2, 1, 4, 3]);
        assert_eq!(
            permutate_vec(&vec!(1, 0, 3, 2), &vec!(1, 2, 3, 4)),
            [2, 1, 4, 3]
        );
        assert_eq!(depermutate(&vec!(3, 0, 1, 2), &[1, 2, 3, 4]), [2, 3, 4, 1]);
        assert_eq!(
            depermutate_vec(&vec!(3, 0, 1, 2), &vec!(1, 2, 3, 4)),
            [2, 3, 4, 1]
        );
    }

    #[test]
    fn symmetric_tests() {
        let p = vec![3, 2, 0, 1];
        let x = [0, 1, 2, 3];
        let x_1 = permutate(&p, &x);
        assert_eq!(depermutate(&p, &x_1), x);
    }
}
