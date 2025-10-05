
use async_nats::{connect, Error, Subject};
use bytes::Bytes;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = connect("nats://localhost:4222").await?;

    let now = Instant::now();
    let subject = Subject::from("foo");
    let dat = Bytes::from("bar");
    for _ in 0..10_000_000 {
        client.publish(subject.clone(), dat.clone()).await?;
    }
    client.flush().await?;

    println!("published in {:?}", now.elapsed());

    Ok(())
}