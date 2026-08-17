use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Command shape shared by both prototype languages.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SseEvent {
    seq: u64,
    label: String,
    payload: String,
    ts: i64,
}

/// Adapter boundary (KeychainStore). Production would wrap Security.framework
/// or a cross-platform keyring crate. The spike ships a noop.
#[allow(dead_code)]
trait KeychainStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), String>;
}

#[allow(dead_code)]
struct NoopKeychain;
impl KeychainStore for NoopKeychain {
    fn get(&self, _key: &str) -> Option<Vec<u8>> { None }
    fn set(&self, _key: &str, _value: &[u8]) -> Result<(), String> { Ok(()) }
}

/// Mode selector (matches argv[1])
#[derive(Debug)]
enum Mode {
    Idle,
    Sqlite,
    Sse,
}

impl Mode {
    fn from_args() -> Mode {
        let arg = env::args().nth(1).unwrap_or_else(|| "idle".into());
        match arg.as_str() {
            "idle" => Mode::Idle,
            "sqlite" => Mode::Sqlite,
            "sse" => Mode::Sse,
            _ => Mode::Idle,
        }
    }
}

fn now_ms() -> i64 {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64) * 1000 + (d.subsec_millis() as i64)
}

/// SQLite benchmark: opens a WAL-mode DB, inserts N rows in one transaction,
/// and reports per-op p50/p95/max plus total wall time.
/// Statement lifecycle: prepare once inside the transaction, reuse N times
/// (matches Go's tx.Prepare + stmt.Exec pattern exactly).
fn run_sqlite_bench(db_path: &str, n: usize) -> Result<(), String> {
    // Clean up prior run — symmetric with Go's os.Remove/Remove("...-wal"/"-shm").
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{}", db_path, suffix);
        std::fs::remove_file(&path).ok();
    }
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS events (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             seq INTEGER NOT NULL,
             payload TEXT NOT NULL,
             ts INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq);",
    ).map_err(|e| e.to_string())?;

    let mut tx_times: Vec<f64> = Vec::with_capacity(n);
    let start = Instant::now();
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    // Prepare once, reuse N times (symmetric with Go's tx.Prepare).
    let mut stmt = tx
        .prepare("INSERT INTO events (seq, payload, ts) VALUES (?1, ?2, ?3)")
        .map_err(|e| e.to_string())?;
    for i in 0..n {
        let t0 = Instant::now();
        stmt.execute(
            params![i as i64, format!("payload-{}", i), now_ms()],
        ).map_err(|e| e.to_string())?;
        let dt = t0.elapsed().as_secs_f64() * 1000.0;
        tx_times.push(dt);
    }
    stmt.finalize().map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    let total = start.elapsed().as_secs_f64();

    tx_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = tx_times[tx_times.len() / 2];
    // p95 formula: nearest-rank ceil, 0-indexed — same as Go and Python driver.
    let p95_idx = ((n as f64 * 0.95).ceil() as usize).saturating_sub(1);
    let p95 = tx_times[p95_idx];
    let max = tx_times.last().unwrap_or(&0.0);

    println!(
        "SQLITE_WAL result={{\"n\":{},\"total_ms\":{:.3},\"p50_ms\":{:.6},\"p95_ms\":{:.6},\"max_ms\":{:.6}}}",
        n, total * 1000.0, p50, p95, max
    );
    Ok(())
}

/// SSE server stub: listens on 127.0.0.1:4097, accepts POST /sse, returns a
/// server-sent event per request. Uses axum's SSE response.
async fn run_sse_server() -> Result<(), String> {
    let store: Arc<Mutex<Connection>> = Arc::new(Mutex::new(
        Connection::open_in_memory().map_err(|e| e.to_string())?
    ));

    let app = Router::new()
        .route("/health", get(health))
        .route("/sse", post(post_sse))
        .with_state(store);

    let addr: SocketAddr = ([127, 0, 0, 1], 4097).into();
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn health() -> &'static str { "ok" }

async fn post_sse(
    State(_db): State<Arc<Mutex<Connection>>>,
    Json(ev): Json<SseEvent>,
) -> Result<String, (StatusCode, String)> {
    let body = serde_json::to_string(&ev).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(format!("data: {}\n\n", body))
}

/// Idle: just start, print a token line, then sleep forever.
fn run_idle() -> Result<(), String> {
    {
        let mut h = std::io::stdout().lock();
        writeln!(h, "READY").map_err(|e| e.to_string())?;
        h.flush().map_err(|e| e.to_string())?;
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn main() -> Result<(), String> {
    let mode = Mode::from_args();
    // Print a consistent READY token for non-idle modes too.
    if !matches!(mode, Mode::Idle) {
        let mut h = std::io::stdout().lock();
        writeln!(h, "READY").map_err(|e| e.to_string())?;
        h.flush().map_err(|e| e.to_string())?;
    }

    match mode {
        Mode::Idle => run_idle(),
        Mode::Sqlite => {
            let db = env::args().nth(2).unwrap_or_else(|| {
                let root = env::var("SPIKE_ROOT").unwrap_or_else(|_| ".".to_string());
                format!("{}/data/test-rust.db", root)
            });
            let n: usize = env::args()
                .nth(3)
                .unwrap_or_else(|| "5000".to_string())
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            run_sqlite_bench(&db, n)?;
            Ok(())
        }
        Mode::Sse => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(run_sse_server())
        }
    }
}

#[allow(dead_code)]
fn _keychain_boundary_demo() -> Box<dyn KeychainStore> {
    Box::new(NoopKeychain)
}
