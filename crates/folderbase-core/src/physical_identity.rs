#[cfg(test)]
mod tests {
    use super::PhysicalIdentity;

    #[test]
    fn windows_identity_uses_all_128_file_id_bits() {
        let legacy_collision_a = PhysicalIdentity::windows(
            0x1020_3040_5060_7080,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
                0xe0, 0xf0, 0x01,
            ],
        );
        let legacy_collision_b = PhysicalIdentity::windows(
            0x1020_3040_5060_7080,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ],
        );

        assert_ne!(
            legacy_collision_a, legacy_collision_b,
            "equal volume and legacy low 64-bit file index cannot authorize a foreign ReFS file"
        );
    }
}
