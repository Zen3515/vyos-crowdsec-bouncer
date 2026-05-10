use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use futures_util::Future;
use rand::{thread_rng, Rng};

pub fn read_file(path: &Path) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(buf)
}

pub(crate) fn retry_backoff(retries: u64, cap: u64) -> Duration {
    let shift = retries.min(10) as u32;
    let base = 25u64.saturating_mul(1u64 << shift);
    let jitter = thread_rng().gen_range(0..25);
    Duration::from_millis(u64::min(cap, base.saturating_add(jitter)))
}

pub async fn retry_op<Fut, T, E, F>(retries: u64, f: F) -> Result<T, E>
where
    E: std::fmt::Debug,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    let mut current_retries = 0;
    let mut f = f;
    loop {
        let result = f().await;
        match result {
            Ok(t) => return Ok(t),
            Err(err) if current_retries < retries => {
                current_retries += 1;
                tracing::error!(?err, retry = current_retries, "Failed iteration");
                tokio::time::sleep(retry_backoff(current_retries, 1000)).await;
            }
            Err(err) => {
                tracing::error!(?err, "Ran out of retries");
                return Err(err);
            }
        }
    }
}
