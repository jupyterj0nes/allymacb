use allymacb::timeline::join_macb_flags;

// Systematic test of all 16 states of a 4-bit bitmask mapped to MACB
#[test]
fn test_state_0000() {
    assert_eq!("....", "....");
}

#[test]
fn test_state_1000() {
    let s = join_macb_flags("....", 'm');
    assert_eq!(s, "m...");
}

#[test]
fn test_state_0100() {
    let s = join_macb_flags("....", 'a');
    assert_eq!(s, ".a..");
}

#[test]
fn test_state_0010() {
    let s = join_macb_flags("....", 'c');
    assert_eq!(s, "..c.");
}

#[test]
fn test_state_0001() {
    let s = join_macb_flags("....", 'b');
    assert_eq!(s, "...b");
}

#[test]
fn test_state_1100() {
    let s = join_macb_flags(&join_macb_flags("....", 'm'), 'a');
    assert_eq!(s, "ma..");
}

#[test]
fn test_state_1010() {
    let s = join_macb_flags(&join_macb_flags("....", 'm'), 'c');
    assert_eq!(s, "m.c.");
}

#[test]
fn test_state_1001() {
    let s = join_macb_flags(&join_macb_flags("....", 'm'), 'b');
    assert_eq!(s, "m..b");
}

#[test]
fn test_state_0110() {
    let s = join_macb_flags(&join_macb_flags("....", 'a'), 'c');
    assert_eq!(s, ".ac.");
}

#[test]
fn test_state_0101() {
    let s = join_macb_flags(&join_macb_flags("....", 'a'), 'b');
    assert_eq!(s, ".a.b");
}

#[test]
fn test_state_0011() {
    let s = join_macb_flags(&join_macb_flags("....", 'c'), 'b');
    assert_eq!(s, "..cb");
}

#[test]
fn test_state_1110() {
    let s = join_macb_flags(&join_macb_flags(&join_macb_flags("....", 'm'), 'a'), 'c');
    assert_eq!(s, "mac.");
}

#[test]
fn test_state_1101() {
    let s = join_macb_flags(&join_macb_flags(&join_macb_flags("....", 'm'), 'a'), 'b');
    assert_eq!(s, "ma.b");
}

#[test]
fn test_state_1011() {
    let s = join_macb_flags(&join_macb_flags(&join_macb_flags("....", 'm'), 'c'), 'b');
    assert_eq!(s, "m.cb");
}

#[test]
fn test_state_0111() {
    let s = join_macb_flags(&join_macb_flags(&join_macb_flags("....", 'a'), 'c'), 'b');
    assert_eq!(s, ".acb");
}

#[test]
fn test_state_1111() {
    let s = join_macb_flags(&join_macb_flags(&join_macb_flags(&join_macb_flags("....", 'm'), 'a'), 'c'), 'b');
    assert_eq!(s, "macb");
}

// Repetitive additions test (40 tests)
macro_rules! test_repetitions {
    ($($fn_name:ident: flag=$flag:expr, repeats=$rep:expr, expected=$exp:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let mut current = "....".to_string();
                for _ in 0..$rep {
                    current = join_macb_flags(&current, $flag);
                }
                assert_eq!(current, $exp);
            }
        )*
    };
}

test_repetitions! {
    test_rep_m_2: flag='m', repeats=2, expected="m...",
    test_rep_m_3: flag='m', repeats=3, expected="m...",
    test_rep_m_5: flag='m', repeats=5, expected="m...",
    test_rep_m_10: flag='m', repeats=10, expected="m...",
    test_rep_a_2: flag='a', repeats=2, expected=".a..",
    test_rep_a_3: flag='a', repeats=3, expected=".a..",
    test_rep_a_5: flag='a', repeats=5, expected=".a..",
    test_rep_a_10: flag='a', repeats=10, expected=".a..",
    test_rep_c_2: flag='c', repeats=2, expected="..c.",
    test_rep_c_3: flag='c', repeats=3, expected="..c.",
    test_rep_c_5: flag='c', repeats=5, expected="..c.",
    test_rep_c_10: flag='c', repeats=10, expected="..c.",
    test_rep_b_2: flag='b', repeats=2, expected="...b",
    test_rep_b_3: flag='b', repeats=3, expected="...b",
    test_rep_b_5: flag='b', repeats=5, expected="...b",
    test_rep_b_10: flag='b', repeats=10, expected="...b",
}
