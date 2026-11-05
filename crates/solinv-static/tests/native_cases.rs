//! Base/head pairs from an adversarial review of the native reader: each
//! drops or keeps a check in a way the reader once got wrong. The number is
//! how many warnings the pair must give.

use solinv_static::native::{diff, NativeChecks};
use std::path::Path;

const CASES: &[(&str, usize)] = &[
    ("c01_trailing_return_err", 1),
    ("c01b_control", 1),
    ("c02_rename_and_drop", 1),
    ("c03_inline_index", 1),
    ("c04_whole_slice", 1),
    ("c05_flag_helper_body", 1),
    ("c05_flag_helper_body_ctl", 1),
    ("c06_pending_helper_body", 1),
    ("c06_pending_helper_body_ctl", 1),
    ("c07_arm_split_asym", 1),
    ("c07b_arm_split_asym2", 1),
    ("c07c", 1),
    ("c09_ctl", 1),
    ("c09_pred_param_named_owner", 1),
    ("c10_pred_method_on_param", 1),
    ("c12_extern_c_entry", 0),
    ("c13_doc_comment_entry", 0),
    ("c14_field_canon_collision", 1),
    ("c16_cfg_duplicate_helper", 1),
    ("c17_closure_shadow_panic", 1),
    ("c18_gutted_helper", 1),
    ("c18b", 1),
    ("c19_authority_only_signs", 1),
    ("c19b", 1),
    ("c20_iter_style", 1),
    ("c21_nonascii_string_in_cond", 1),
    // Accounts bound above the `match`, a check dropped in one arm.
    ("n02_arm_preamble_binding", 1),
    // A check every arm shared, moved above the `match`: still made.
    ("fp1", 0),
];

#[test]
fn review_cases() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/native_cases");
    let mut wrong = Vec::new();
    for (case, want) in CASES {
        let read = |v: &str| NativeChecks::read(&dir.join(case).join(format!("{v}.rs"))).unwrap();
        let got = diff(&read("base"), &read("head"));
        if got.len() != *want {
            wrong.push(format!("{case}: want {want}, got {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
