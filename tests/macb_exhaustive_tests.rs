use allymacb::timeline::join_macb_flags;

#[test]
fn test_macb_empty_base() {
    assert_eq!(join_macb_flags("....", 'm'), "m...");
    assert_eq!(join_macb_flags("....", 'a'), ".a..");
    assert_eq!(join_macb_flags("....", 'c'), "..c.");
    assert_eq!(join_macb_flags("....", 'b'), "...b");
}

#[test]
fn test_macb_invalid_length_base() {
    assert_eq!(join_macb_flags("", 'm'), "m...");
    assert_eq!(join_macb_flags("..", 'a'), ".a..");
    assert_eq!(join_macb_flags(".....", 'c'), "..c.");
}

#[test]
fn test_macb_unknown_flag() {
    assert_eq!(join_macb_flags("m...", 'x'), "m...");
    assert_eq!(join_macb_flags("....", '?'), "....");
    assert_eq!(join_macb_flags("....", 'M'), "...."); // case-sensitive
}

#[test]
fn test_macb_idempotent() {
    assert_eq!(join_macb_flags("m...", 'm'), "m...");
    assert_eq!(join_macb_flags(".a..", 'a'), ".a..");
    assert_eq!(join_macb_flags("..c.", 'c'), "..c.");
    assert_eq!(join_macb_flags("...b", 'b'), "...b");
    assert_eq!(join_macb_flags("macb", 'm'), "macb");
    assert_eq!(join_macb_flags("macb", 'a'), "macb");
    assert_eq!(join_macb_flags("macb", 'c'), "macb");
    assert_eq!(join_macb_flags("macb", 'b'), "macb");
}

// 2-flag combinations
#[test]
fn test_macb_pairs_ma() {
    let s = join_macb_flags("m...", 'a');
    assert_eq!(s, "ma..");
    let s2 = join_macb_flags(".a..", 'm');
    assert_eq!(s2, "ma..");
}

#[test]
fn test_macb_pairs_mc() {
    let s = join_macb_flags("m...", 'c');
    assert_eq!(s, "m.c.");
    let s2 = join_macb_flags("..c.", 'm');
    assert_eq!(s2, "m.c.");
}

#[test]
fn test_macb_pairs_mb() {
    let s = join_macb_flags("m...", 'b');
    assert_eq!(s, "m..b");
    let s2 = join_macb_flags("...b", 'm');
    assert_eq!(s2, "m..b");
}

#[test]
fn test_macb_pairs_ac() {
    let s = join_macb_flags(".a..", 'c');
    assert_eq!(s, ".ac.");
    let s2 = join_macb_flags("..c.", 'a');
    assert_eq!(s2, ".ac.");
}

#[test]
fn test_macb_pairs_ab() {
    let s = join_macb_flags(".a..", 'b');
    assert_eq!(s, ".a.b");
    let s2 = join_macb_flags("...b", 'a');
    assert_eq!(s2, ".a.b");
}

#[test]
fn test_macb_pairs_cb() {
    let s = join_macb_flags("..c.", 'b');
    assert_eq!(s, "..cb");
    let s2 = join_macb_flags("...b", 'c');
    assert_eq!(s2, "..cb");
}

// 3-flag combinations
#[test]
fn test_macb_triplets_mac() {
    let s = join_macb_flags("ma..", 'c');
    assert_eq!(s, "mac.");
}

#[test]
fn test_macb_triplets_mab() {
    let s = join_macb_flags("ma..", 'b');
    assert_eq!(s, "ma.b");
}

#[test]
fn test_macb_triplets_mcb() {
    let s = join_macb_flags("m.c.", 'b');
    assert_eq!(s, "m.cb");
}

#[test]
fn test_macb_triplets_acb() {
    let s = join_macb_flags(".ac.", 'b');
    assert_eq!(s, ".acb");
}

// 4-flag combination
#[test]
fn test_macb_full_from_mac() {
    assert_eq!(join_macb_flags("mac.", 'b'), "macb");
}

#[test]
fn test_macb_full_from_mab() {
    assert_eq!(join_macb_flags("ma.b", 'c'), "macb");
}

#[test]
fn test_macb_full_from_mcb() {
    assert_eq!(join_macb_flags("m.cb", 'a'), "macb");
}

#[test]
fn test_macb_full_from_acb() {
    assert_eq!(join_macb_flags(".acb", 'm'), "macb");
}

// Chain building permutations
macro_rules! generate_permutation_tests {
    ($($name:ident: [$($flag:expr),+]),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let mut current = "....".to_string();
                $(
                    current = join_macb_flags(&current, $flag);
                )+
                assert_eq!(current, "macb");
            }
        )*
    };
}

generate_permutation_tests! {
    test_perm_m_a_c_b: ['m', 'a', 'c', 'b'],
    test_perm_m_a_b_c: ['m', 'a', 'b', 'c'],
    test_perm_m_c_a_b: ['m', 'c', 'a', 'b'],
    test_perm_m_c_b_a: ['m', 'c', 'b', 'a'],
    test_perm_m_b_a_c: ['m', 'b', 'a', 'c'],
    test_perm_m_b_c_a: ['m', 'b', 'c', 'a'],
    test_perm_a_m_c_b: ['a', 'm', 'c', 'b'],
    test_perm_a_m_b_c: ['a', 'm', 'b', 'c'],
    test_perm_a_c_m_b: ['a', 'c', 'm', 'b'],
    test_perm_a_c_b_m: ['a', 'c', 'b', 'm'],
    test_perm_a_b_m_c: ['a', 'b', 'm', 'c'],
    test_perm_a_b_c_m: ['a', 'b', 'c', 'm'],
    test_perm_c_m_a_b: ['c', 'm', 'a', 'b'],
    test_perm_c_m_b_a: ['c', 'm', 'b', 'a'],
    test_perm_c_a_m_b: ['c', 'a', 'm', 'b'],
    test_perm_c_a_b_m: ['c', 'a', 'b', 'm'],
    test_perm_c_b_m_a: ['c', 'b', 'm', 'a'],
    test_perm_c_b_a_m: ['c', 'b', 'a', 'm'],
    test_perm_b_m_a_c: ['b', 'm', 'a', 'c'],
    test_perm_b_m_c_a: ['b', 'm', 'c', 'a'],
    test_perm_b_a_m_c: ['b', 'a', 'm', 'c'],
    test_perm_b_a_c_m: ['b', 'a', 'c', 'm'],
    test_perm_b_c_m_a: ['b', 'c', 'm', 'a'],
    test_perm_b_c_a_m: ['b', 'c', 'a', 'm'],
}
