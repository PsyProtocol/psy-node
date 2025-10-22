use scylla::{client::session::Session, statement::{batch::Batch, prepared::PreparedStatement}};



pub const fn u64_to_i64_exact(num: u64) -> i64 {
    i64::from_ne_bytes(num.to_ne_bytes())
}
pub const fn i64_to_u64_exact(num: i64) -> u64 {
    u64::from_ne_bytes(num.to_ne_bytes())
}
pub const fn u8_to_i8_exact(num: u8) -> i8 {
    i8::from_ne_bytes([num])
}
pub const fn i8_to_u8_exact(num: i8) -> u8 {
    u8::from_ne_bytes(num.to_ne_bytes())
}

pub const fn convert_checkpoint_id_to_i64(checkpoint_id: u64) -> i64 {
    if checkpoint_id > (i64::MAX as u64) {
        i64::MAX
    } else {
        checkpoint_id as i64
    }
}

pub const fn convert_i64_to_checkpoint_id(checkpoint_id: i64) -> u64 {
    if checkpoint_id < 0 {
        i64::MAX as u64
    } else {
        checkpoint_id as u64
    }
}


pub fn calc_best_batch_size(num_nodes: usize, batch_sizes: &[usize]) -> usize {

    if batch_sizes.is_empty() {
        return 1;
    }
    let batch_size = batch_sizes
        .iter()
        .find(|&&size| num_nodes >= size && (num_nodes % size == 0 || num_nodes / size >= 1))
        .unwrap_or(&batch_sizes[batch_sizes.len() - 1]);

    *batch_size
}
/*
// commented out because we switched to using PreparedStatement directly, I think this is ok
pub async fn generate_batch_prepared_statement(session: &Session, statement: &Statement, batch_size: usize) -> anyhow::Result<Batch> {
    if batch_size == 0 {
        anyhow::bail!("Batch size must be greater than 0");
    }
    let mut batch = Batch::default();
    for _ in 0..batch_size {
        batch.append_statement(statement.clone());
    }

    let prepared = session.prepare_batch(&batch).await?;
    Ok(prepared)
}
*/
pub async fn generate_batch_prepared_statement(session: &Session, statement: &PreparedStatement, batch_size: usize) -> anyhow::Result<Batch> {
    if batch_size == 0 {
        anyhow::bail!("Batch size must be greater than 0");
    }
    let mut batch = Batch::default();
    for _ in 0..batch_size {
        batch.append_statement(statement.clone());
    }

    let prepared = session.prepare_batch(&batch).await?;
    Ok(prepared)
}


pub fn generate_batch_pre_prepared_statements(statement: &PreparedStatement, batch_size: usize) -> Batch {

    let mut batch = Batch::default();
    for _ in 0..batch_size {
        batch.append_statement(statement.clone());
    }

    batch
}

#[cfg(test)]
mod tests {
    use std::ops::{Shl, Shr};

    use super::*;


    fn ensure_u8_i8_round_trip(x: u8) {
        let y = u8_to_i8_exact(x);
        let z = i8_to_u8_exact(y);
        assert_eq!(x, z, "Failed round trip for u8 value: {}", x);
    }

    fn ensure_i8_u8_round_trip(x: i8) {
        let y = i8_to_u8_exact(x);
        let z = u8_to_i8_exact(y);
        assert_eq!(x, z, "Failed round trip for i8 value: {}", x);
    }

    fn ensure_u64_i64_round_trip(x: u64) {
        let y = u64_to_i64_exact(x);
        let z = i64_to_u64_exact(y);
        assert_eq!(x, z, "Failed round trip for value: {}", x);
    }
    fn ensure_i64_u64_round_trip(x: i64) {
        let y = i64_to_u64_exact(x);
        let z = u64_to_i64_exact(y);
        assert_eq!(x, z, "Failed round trip for value: {}", x);
    }
    #[test]
    fn test_u64_i64_round_trips() { 
        ensure_u64_i64_round_trip(0);
        ensure_u64_i64_round_trip(1);
        ensure_u64_i64_round_trip(123456789);
        ensure_u64_i64_round_trip(i64::MAX as u64);
        ensure_u64_i64_round_trip((i64::MAX as u64) + 1);
        ensure_u64_i64_round_trip((i64::MAX as u64) + 200);
        ensure_u64_i64_round_trip((i64::MAX as u64) + 256);
        ensure_u64_i64_round_trip(u64::MAX);
        ensure_u64_i64_round_trip(u64::MAX-1);
        ensure_u64_i64_round_trip(u64::MAX-256);
        for i in 0..64 {
            ensure_u64_i64_round_trip(1u64.shl(i));
            if i > 0 {
                ensure_u64_i64_round_trip((1u64.shl(i))-1u64);
                ensure_u64_i64_round_trip((1u64.shl(i))+1u64);
            }
            ensure_u64_i64_round_trip(u64::MAX.shr(i));
        }
        for i in 0..63 {
            ensure_i64_u64_round_trip(1i64.shl(i));
            if i > 0 {
                ensure_i64_u64_round_trip((1i64.shl(i))-1i64);
                ensure_i64_u64_round_trip((1i64.shl(i))+1i64);
            }
            ensure_i64_u64_round_trip(i64::MAX.shr(i));
            ensure_i64_u64_round_trip(-1i64 * (1i64.shl(i)));
            if i > 0 {
                ensure_i64_u64_round_trip(-1i64 * ((1i64.shl(i))-1i64));
                ensure_i64_u64_round_trip(-1i64 * ((1i64.shl(i))+1i64));
            }
            ensure_i64_u64_round_trip(-1i64 * (i64::MAX.shr(i)));
        }
        // fuzz some random values
        for _ in 0..10000 {
            let x = rand::random::<u64>();
            ensure_u64_i64_round_trip(x);
            let y = rand::random::<i64>();
            ensure_i64_u64_round_trip(y);
        }
    }

    #[test]
    fn test_u8_i8_round_trips() {
        // Exhaustive test for all u8 values
        for i in u8::MIN..=u8::MAX {
            ensure_u8_i8_round_trip(i);
        }

        // Exhaustive test for all i8 values
        // A simple for loop works fine as the iterator is smart enough to handle the range.
        for i in i8::MIN..=i8::MAX {
            ensure_i8_u8_round_trip(i);
        }
    }

    #[test]
    fn test_convert_checkpoint_id_to_i64_conversion() {
        // Values within the i64 range
        assert_eq!(convert_checkpoint_id_to_i64(0), 0);
        assert_eq!(convert_checkpoint_id_to_i64(1), 1);
        assert_eq!(convert_checkpoint_id_to_i64(123456789), 123456789);
        assert_eq!(convert_checkpoint_id_to_i64(i64::MAX as u64), i64::MAX);

        // Values outside the i64 range (should be clamped to i64::MAX)
        assert_eq!(convert_checkpoint_id_to_i64((i64::MAX as u64) + 1), i64::MAX);
        assert_eq!(convert_checkpoint_id_to_i64((i64::MAX as u64) + 1000), i64::MAX);
        assert_eq!(convert_checkpoint_id_to_i64(u64::MAX), i64::MAX);
        assert_eq!(convert_checkpoint_id_to_i64(u64::MAX-1), i64::MAX);
        assert_eq!(convert_checkpoint_id_to_i64(u64::MAX-0x100), i64::MAX);
        assert_eq!(convert_checkpoint_id_to_i64(u64::MAX-0xff), i64::MAX);
        for _ in 0..1000 {
            let x = (i64::MAX as u64) + 1 + rand::random::<u64>() % (u64::MAX - (i64::MAX as u64));
            assert_eq!(convert_checkpoint_id_to_i64(x), i64::MAX, "Failed for input value: {}", x);
        }



        // fuzz some random values within the i64 range
        for _ in 0..10000 {
            let x = rand::random::<u64>() % ((i64::MAX as u64)+1);
            assert_eq!(convert_checkpoint_id_to_i64(x), x as i64, "Failed for input value: {}", x);
        }

    }

    #[test]
    fn test_convert_i64_to_checkpoint_id_conversion() {
        // Positive values and zero
        assert_eq!(convert_i64_to_checkpoint_id(0), 0);
        assert_eq!(convert_i64_to_checkpoint_id(1), 1);
        assert_eq!(convert_i64_to_checkpoint_id(123456789), 123456789);
        assert_eq!(convert_i64_to_checkpoint_id(i64::MAX), i64::MAX as u64);

        // Negative values (should be clamped to i64::MAX)
        assert_eq!(convert_i64_to_checkpoint_id(-1), i64::MAX as u64);
        assert_eq!(convert_i64_to_checkpoint_id(-123456789), i64::MAX as u64);
        assert_eq!(convert_i64_to_checkpoint_id(i64::MIN), i64::MAX as u64);

        // fuzz some random values in the i64:MAX to u64::MAX range
        let base: u64 = u64::MAX - (i64::MAX as u64);
        for _ in 0..10000 {
            let x = (i64::MAX as u64)+ (rand::random::<u64>() % base);
            assert_eq!(convert_i64_to_checkpoint_id(u64_to_i64_exact(x)), i64::MAX as u64, "Failed for input value: {}", x);
        }

        // fuzz some random values within the i64 range
        for _ in 0..10000 {
            let x = rand::random::<i64>();
            let expected = if x < 0 { i64::MAX as u64 } else { x as u64 };
            assert_eq!(convert_i64_to_checkpoint_id(x), expected, "Failed for input value: {}", x);
        }
    }
}