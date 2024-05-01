pub fn permutate_vec<'a, T>(p: &[usize], x: &'a [T]) -> Vec<&'a T> {
    assert_eq!(p.len(), x.len());
    p.iter().map(|&index| &x[index]).collect()
}

pub fn depermutate_vec<T: Clone + Copy>(p: &Vec<usize>, x: &Vec<T>) -> Vec<T> {
    assert_eq!(p.len(), x.len());

    let mut result = vec![x[0]; p.len()];
    for i in 0..p.len() {
        result[p[i]] = x[i];
    }
    result
}

pub fn permutate<T: Copy, const N: usize>(p: &[usize], x: &[T; N]) -> [T; N] {
    assert_eq!(p.len(), x.len());

    let mut result = [x[0]; N];
    for (i, &pi) in p.iter().enumerate() {
        result[i] = x[pi];
    }
    result
}

// use std::mem::MaybeUninit;

// pub fn permutate<T: Copy, const N: usize>(p: &[usize], x: &[T; N]) -> [T; N] {
//     let mut result = [MaybeUninit::uninit(); N];
//     for (i, &pi) in p.iter().enumerate() {
//         unsafe {
//             *result[i].as_mut_ptr() = x[pi];
//         }
//     }
//     unsafe { std::mem::transmute_copy(&result) }
// }

pub fn depermutate<T: Clone + Copy, const N: usize>(p: &Vec<usize>, x: &[T; N]) -> [T; N] {
    assert_eq!(p.len(), x.len());

    let mut result = [x[0].clone(); N];
    for i in 0..p.len() {
        result[p[i]] = x[i];
    }
    result
}

// pub fn find_conversion_key(pa: &Vec<usize>, pb: &Vec<usize>) -> Vec<usize> {
//     assert_eq!(pa.len(), pb.len());
//     let n = pa.len();
//     let mut pc = vec![0; n];
//     for i in 0..n {
//         for j in 0..n {
//             if pa[i] == pb[j] {
//                 pc[j] = i;
//                 break;
//             }
//         }
//     }
//     pc
// }

pub fn find_conversion_key(pa: &Vec<usize>, pb: &Vec<usize>) -> Vec<usize> {
    let length = pa.len();
    let mut index_pa: Vec<usize> = (0..length).collect();
    let mut index_pb = index_pa.clone();

    index_pa.sort_unstable_by_key(|&i| pa[i]);
    index_pb.sort_unstable_by_key(|&i| pb[i]);

    let mut pc = vec![0; length];
    for i in 0..length {
        pc[index_pb[i]] = index_pa[i];
    }

    pc
}

#[cfg(test)]
mod permutation_tests {
    use crate::permutation::{depermutate, depermutate_vec, permutate, permutate_vec};

    use super::find_conversion_key;

    #[test]
    fn correctness_check() {
        assert_eq!(permutate(&vec!(1, 0, 3, 2), &[1, 2, 3, 4]), [2, 1, 4, 3]);
        assert_eq!(
            permutate_vec(&vec!(1, 0, 3, 2), &vec!(1, 2, 3, 4)),
            [&2, &1, &4, &3]
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

    #[test]
    fn find_conversion_key_test() {
        let a = vec![9, 14, 15, 0, 4, 5, 12, 1, 11, 7, 2, 6, 13, 3, 8, 10];
        let b = vec![1, 14, 10, 15, 11, 3, 4, 7, 5, 12, 8, 13, 9, 0, 2, 6];
        let expected = [7, 1, 15, 2, 8, 13, 4, 9, 5, 6, 14, 12, 0, 3, 10, 11];
        assert_eq!(find_conversion_key(&a, &b), expected)
    }
}
