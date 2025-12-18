use rand::{Rng, seq::SliceRandom, thread_rng};

pub fn unique_random_u64_array_in_range(min_inclusive: u64, max_exclusive: u64, count: usize) -> anyhow::Result<Vec<u64>> {
    if min_inclusive >= max_exclusive {
        anyhow::bail!("Invalid range: min_inclusive must be less than max_exclusive");
    }

    let range_size = (max_exclusive - min_inclusive) as usize;
    if range_size < count {
        anyhow::bail!("Range size is smaller than count; cannot generate enough unique numbers");
    } else if range_size == 1 {
        return Ok(vec![min_inclusive]);
    } else if range_size == count {
        return Ok((min_inclusive..max_exclusive).collect());
    }

    let mut rng = thread_rng();
    if count > range_size / 2 {
        let compliment_count = range_size - count;
        let mut rand_not_in_range = std::collections::HashSet::with_capacity(compliment_count);
        while rand_not_in_range.len() < compliment_count {
            let num = rng.gen_range(min_inclusive..max_exclusive);
            rand_not_in_range.insert(num);
        }
        let mut rand_not_in_range = rand_not_in_range.into_iter().collect::<Vec<u64>>();
        rand_not_in_range.sort_unstable();

        let mut output = Vec::with_capacity(count);
        let mut current = min_inclusive;

        for &excluded in &rand_not_in_range {
            while current < excluded {
                output.push(current);
                current += 1;
            }
            current += 1; // skip the excluded number
        }
        if current < max_exclusive {
            for i in current..max_exclusive {
                output.push(i);
            }
        }
        output.shuffle(&mut rng);
        Ok(output)
    } else {
        let mut unique_numbers = std::collections::HashSet::with_capacity(count);
        while unique_numbers.len() < count {
            let num = rng.gen_range(min_inclusive..max_exclusive);
            unique_numbers.insert(num);
        }
        let mut result = unique_numbers.into_iter().collect::<Vec<u64>>();
        result.shuffle(&mut rng);
        Ok(result)
    }
}


#[cfg(test)]
mod tests {
    use super::unique_random_u64_array_in_range;
    #[test]
    fn test_unique_random_u64_array_in_range() {
        let result = unique_random_u64_array_in_range(10, 20, 5).unwrap();
        assert_eq!(result.len(), 5);
        for &num in &result {
            assert!(num >= 10 && num < 20);
        }
    }

    #[test]
    fn test_unique_random_u64_array_in_range_full_range() {
        let result = unique_random_u64_array_in_range(0, 5, 5).unwrap();
        assert_eq!(result.len(), 5);
        let mut expected: Vec<u64> = (0..5).collect();
        expected.sort_unstable();
        let mut result_sorted = result.clone();
        result_sorted.sort_unstable();
        assert_eq!(result_sorted, expected);
    }
    #[test]
    fn test_unique_random_u64_array_in_range_single_value() {
        let result = unique_random_u64_array_in_range(42, 43, 1).unwrap();
        assert_eq!(result, vec![42]);
    }
    #[test]
    fn test_unique_random_u64_array_in_range_invalid_range() {
        let result = unique_random_u64_array_in_range(10, 5, 3);
        assert!(result.is_err());
    }
    #[test]
    fn test_unique_random_u64_array_large_range() {
        let result = unique_random_u64_array_in_range(500_000, u32::MAX as u64, 100_000).unwrap();
        assert_eq!(result.len(), 100_000);
        let mut unique_check = std::collections::HashSet::new();
        for &num in &result {
            assert!(num < u32::MAX as u64 && num >= 500_000);
            unique_check.insert(num);
        }
        assert_eq!(unique_check.len(), result.len());

    }
    #[test]
    fn test_unique_random_u64_array_small_range_near_count() {
        let result = unique_random_u64_array_in_range(500_000, 600_003, 100_000).unwrap();
        assert_eq!(result.len(), 100_000);
        let mut unique_check = std::collections::HashSet::new();
        for &num in &result {
            assert!(num < 600_003 && num >= 500_000);
            unique_check.insert(num);
        }
        assert_eq!(unique_check.len(), result.len());

    }
}