pub trait QBlobStructHeaderBase: Sized {
    const BLOB_MAGIC: u32;

    // is this blob an array of items
    const IS_ARRAY: bool;

    // is this blob an array of items with a fixed size
    const IS_FIXED_ITEM_ARRAY: bool;

    const HEADER_SIZE: usize;

    // total size of the data including the header
    fn total_size(&self) -> usize;

    // size of the payload (not including the header)
    fn payload_size(&self) -> usize {
        self.total_size() - Self::HEADER_SIZE
    }

    // for non-fixed item arrays or blobs whose values are not fixed size, this will be 0
    fn get_fixed_item_size(&self) -> usize;

    // for non-array types, this will be 1
    fn get_array_length(&self) -> usize;

    fn try_read_header_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn header_to_bytes_vec(&self) -> Vec<u8>;
    fn is_header_valid(&self) -> bool;
}