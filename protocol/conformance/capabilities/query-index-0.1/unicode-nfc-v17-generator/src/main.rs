use std::collections::BTreeMap;
use unicode_normalization::{
    UnicodeNormalization,
    char::{canonical_combining_class, compose},
};

fn main() {
    let mut ccc = BTreeMap::new();
    let mut decompositions = BTreeMap::new();
    let mut compositions = BTreeMap::new();
    for scalar in 0..=0x10ffff {
        let Some(ch) = char::from_u32(scalar) else {
            continue;
        };
        let class = canonical_combining_class(ch);
        if class != 0 {
            ccc.insert(scalar, class);
        }
        let decomposed = ch.nfd().map(u32::from).collect::<Vec<_>>();
        if decomposed != [scalar] {
            decompositions.insert(scalar, decomposed.clone());
        }
        if decomposed.is_empty() {
            continue;
        }
        let mut starter = char::from_u32(decomposed[0]).unwrap();
        let mut last_ccc = 0;
        for scalar in decomposed.into_iter().skip(1) {
            let current = char::from_u32(scalar).unwrap();
            let current_ccc = canonical_combining_class(current);
            if (last_ccc == 0 || last_ccc < current_ccc)
                && let Some(composed) = compose(starter, current)
            {
                compositions.insert((u32::from(starter), scalar), u32::from(composed));
                starter = composed;
                continue;
            }
            if current_ccc == 0 {
                starter = current;
            }
            last_ccc = current_ccc;
        }
    }
    println!("// Generated from unicode-normalization 0.1.25 (Unicode 17.0.0).");
    println!(
        "// crates.io checksum: 5fd4f6878c9cb28d874b009da9e8d183b5abc80117c40bbd187a1fde336be6e8"
    );
    println!(
        "// src/tables.rs SHA-256: 177d5f08019cc8e335444fcab61aabb7f6309f158f6ebbd7525c73c0e532ec44"
    );
    println!("// Derived data; see THIRD_PARTY_NOTICES.md. This module is self-contained.");
    println!("export const UNICODE_NFC_VERSION = Object.freeze([17, 0, 0]);");
    println!("export const CANONICAL_COMBINING_CLASS_V17 = new Map([");
    for (key, value) in ccc {
        println!("  [0x{key:x}, {value}],");
    }
    println!("]);");
    println!("export const CANONICAL_DECOMPOSITION_V17 = new Map([");
    for (key, value) in decompositions {
        let values = value
            .iter()
            .map(|v| format!("0x{v:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  [0x{key:x}, [{values}]],");
    }
    println!("]);");
    println!("export const CANONICAL_COMPOSITION_V17 = new Map([");
    for ((left, right), value) in compositions {
        let key = u64::from(left) * 0x110000 + u64::from(right);
        println!("  [{key}, 0x{value:x}],");
    }
    println!("]);");
}
