use std::time::Duration;



/// Create a new bb8-redis connection pool
///
/// # Arguments
///
/// * `redis_url` - Redis URL to connect to
/// * `pool_size` - Number of connections in the pool
pub async fn new_redis_async_pool(redis_url: &str, pool_size: usize) -> anyhow::Result<bb8::Pool<bb8_redis::RedisConnectionManager>> {
    // Create the connection manager
    let manager = bb8_redis::RedisConnectionManager::new(redis_url)?;

    // Build the pool with similar configuration to fred pool
    let pool = bb8::Pool::builder()
        .max_size(pool_size as u32)
        .connection_timeout(Duration::from_secs(10))
        .build(manager)
        .await?;

    // Optionally add client identification (if supported by redis-rs)
    // This may require getting a connection and executing a command
    if let Ok(role) = std::env::var("QED_ROLE") {
        // Try to set a similar client name if possible
        // Note: bb8-redis doesn't directly expose CLIENT SETNAME
        if let Ok(mut conn) = pool.get().await {
            let _: Result<String, _> = redis::cmd("CLIENT")
                .arg("SETNAME")
                .arg(format!("bb8-{}-pool", role))
                .query_async(&mut *conn)
                .await;
        }
    }

    // Log pool creation
    tracing::info!("✅ Created bb8-redis connection pool with size {}", pool_size);

    Ok(pool)
}

