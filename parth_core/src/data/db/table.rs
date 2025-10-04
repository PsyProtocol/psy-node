
#[pderive::serialize_copy_default]
pub struct QDatabaseTableRoutingKey {
    pub table_id: u64,
    pub table_secondary_routing_id: u64,
    pub connection_id: u32, // for future use, identifies multiple database connections in the same process
}

impl QDatabaseTableRoutingKey {
    pub fn new(table_id: u64, table_secondary_routing_id: u64, connection_id: u32) -> Self {
        Self { table_id, table_secondary_routing_id, connection_id }
    }
    pub fn new_with_empty_secondary_routing_key(table_id: u64) -> Self {
        Self { table_id, table_secondary_routing_id: 0, connection_id: 0 }
    }
    pub fn t_with_empty_secondary_routing_key<T: Into<u64>>(table_id: T) -> Self {
        Self { table_id: table_id.into(), table_secondary_routing_id: 0, connection_id: 0 }
    }
    pub fn t_with_secondary_routing_key<T: Into<u64>, U: Into<u64>>(table_id: T, table_secondary_routing_id: U) -> Self {
        Self { table_id: table_id.into(), table_secondary_routing_id: table_secondary_routing_id.into(), connection_id: 0 }
    }

    pub fn new_with_connection_empty_secondary_routing_key(table_id: u64, connection_id: u32) -> Self {
        Self { table_id, table_secondary_routing_id: 0, connection_id }
    }
    pub fn t_with_connection_empty_secondary_routing_key<T: Into<u64>>(table_id: T, connection_id: u32) -> Self {
        Self { table_id: table_id.into(), table_secondary_routing_id: 0, connection_id }
    }
    pub fn t_with_connection_secondary_routing_key<T: Into<u64>, U: Into<u64>>(table_id: T, table_secondary_routing_id: U, connection_id: u32) -> Self {
        Self { table_id: table_id.into(), table_secondary_routing_id: table_secondary_routing_id.into(), connection_id }
    }
}