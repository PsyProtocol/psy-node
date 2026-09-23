type KeyIndexRow = (Vec<u8>, Vec<u8>, i64, i64);

/// Stores return encoded_key DESC. Keep that order while excluding keys which
/// were not yet present at the requested checkpoint.
pub(super) fn candidates(rows: &[KeyIndexRow], checkpoint: i64) -> impl Iterator<Item = &KeyIndexRow> {
    rows.iter().filter(move |row| row.3 <= checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imt_previous_bucket_selects_largest_visible_key_first() {
        // All keys are in the preceding bucket; their order matches Scylla DESC.
        let rows = vec![
            (vec![1, 0, 90], vec![90], 90, 12),
            (vec![1, 0, 80], vec![80], 80, 10),
            (vec![1, 0, 70], vec![70], 70, 9),
        ];
        assert_eq!(candidates(&rows, 10).map(|row| row.2).collect::<Vec<_>>(), vec![80, 70]);
        assert_eq!(candidates(&rows, 12).next().unwrap().2, 90);
        assert!(candidates(&rows, 8).next().is_none());
        assert!(candidates(&[], 10).next().is_none());
        // A missing leaf may be skipped, but the next candidate must still be
        // the greatest remaining key, not the smallest key in the bucket.
        assert_eq!(candidates(&rows, 12).find(|row| row.2 != 90).unwrap().2, 80);
    }
}
