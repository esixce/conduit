use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};
use rusqlite::Connection;
use serde::Serialize;
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Console event type
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct ConsoleEvent {
    pub id: u64,
    pub timestamp: String,
    pub role: String,
    pub event_type: String,
    pub data: serde_json::Value,
}

pub fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Append-only event log on disk (SQLite). Used for history API and audit trail.
pub struct EventLog {
    conn: std::sync::Mutex<Connection>,
}

impl EventLog {
    pub fn new(storage_dir: &str) -> Result<Self, rusqlite::Error> {
        let path = std::path::Path::new(storage_dir).join("events.db");
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                role      TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data      TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    pub fn append(&self, event: &ConsoleEvent) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (timestamp, role, event_type, data) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                event.timestamp,
                event.role,
                event.event_type,
                serde_json::to_string(&event.data).unwrap_or_default(),
            ],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    pub fn query(
        &self,
        since_id: u64,
        limit: u32,
        role_filter: Option<&str>,
    ) -> Result<Vec<ConsoleEvent>, rusqlite::Error> {
        let limit = limit.min(1000);
        let conn = self.conn.lock().unwrap();
        let mut out = Vec::new();
        if let Some(role) = role_filter {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, role, event_type, data FROM events WHERE id > ?1 AND role = ?2 ORDER BY id ASC LIMIT ?3",
            )?;
            let mapped = stmt.query_map(
                rusqlite::params![since_id as i64, role, limit as i32],
                |row| {
                    let data_str: String = row.get(4)?;
                    let data = serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
                    Ok(ConsoleEvent {
                        id: row.get::<_, i64>(0)? as u64,
                        timestamp: row.get(1)?,
                        role: row.get(2)?,
                        event_type: row.get(3)?,
                        data,
                    })
                },
            )?;
            for row in mapped {
                out.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, role, event_type, data FROM events WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )?;
            let mapped =
                stmt.query_map(rusqlite::params![since_id as i64, limit as i32], |row| {
                    let data_str: String = row.get(4)?;
                    let data = serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
                    Ok(ConsoleEvent {
                        id: row.get::<_, i64>(0)? as u64,
                        timestamp: row.get(1)?,
                        role: row.get(2)?,
                        event_type: row.get(3)?,
                        data,
                    })
                })?;
            for row in mapped {
                out.push(row?);
            }
        }
        Ok(out)
    }
}

/// Single path for emitting console events: persist to log (if present) then broadcast.
#[derive(Clone)]
pub struct ConsoleEmitter {
    tx: broadcast::Sender<ConsoleEvent>,
    log: Option<Arc<EventLog>>,
}

impl ConsoleEmitter {
    pub fn new(tx: broadcast::Sender<ConsoleEvent>, log: Option<Arc<EventLog>>) -> Self {
        Self { tx, log }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConsoleEvent> {
        self.tx.subscribe()
    }

    pub fn event_log(&self) -> Option<Arc<EventLog>> {
        self.log.clone()
    }

    pub fn emit(&self, role: &str, event_type: &str, data: serde_json::Value) {
        let mut event = ConsoleEvent {
            id: 0,
            timestamp: now_ts(),
            role: role.into(),
            event_type: event_type.into(),
            data,
        };
        if let Some(ref log) = self.log {
            if let Ok(id) = log.append(&event) {
                event.id = id;
            }
        }
        println!("[{}] {:<20} {}", event.role, event.event_type, event.data);
        let _ = self.tx.send(event);
    }
}

// ---------------------------------------------------------------------------
// Event router — single event loop, dispatches to registered handlers
// ---------------------------------------------------------------------------

/// Central event dispatcher. One background thread calls `wait_next_event()`,
/// matches on payment hash, and forwards to the registered handler. Events
/// that don't match any handler are logged and acknowledged — they never block
/// other handlers or eat events meant for the node's internal state machine.
pub struct EventRouter {
    waiters:
        std::sync::Mutex<std::collections::HashMap<PaymentHash, std::sync::mpsc::Sender<Event>>>,
    emitter: Arc<ConsoleEmitter>,
    role: std::sync::Mutex<String>,
}

impl EventRouter {
    pub fn new(emitter: Arc<ConsoleEmitter>) -> Self {
        Self {
            waiters: std::sync::Mutex::new(std::collections::HashMap::new()),
            emitter,
            role: std::sync::Mutex::new("node".into()),
        }
    }

    pub fn set_role(&self, role: &str) {
        *self.role.lock().unwrap() = role.into();
    }

    /// Register to receive events for a specific payment hash.
    /// Returns a receiver that will get `PaymentClaimable`, `PaymentReceived`,
    /// `PaymentSuccessful`, or `PaymentFailed` events matching this hash.
    pub fn register(&self, hash: PaymentHash) -> std::sync::mpsc::Receiver<Event> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.waiters.lock().unwrap().insert(hash, tx);
        rx
    }

    /// Unregister a handler (called when the handler is done).
    pub fn unregister(&self, hash: &PaymentHash) {
        self.waiters.lock().unwrap().remove(hash);
    }

    /// Extract payment hash from an event, if it has one.
    pub fn payment_hash_of(event: &Event) -> Option<PaymentHash> {
        match event {
            Event::PaymentClaimable { payment_hash, .. } => Some(*payment_hash),
            Event::PaymentReceived { payment_hash, .. } => Some(*payment_hash),
            Event::PaymentSuccessful { payment_hash, .. } => Some(*payment_hash),
            Event::PaymentFailed {
                payment_hash: Some(hash),
                ..
            } => Some(*hash),
            _ => None,
        }
    }

    /// Run the central event loop. Call from a dedicated background thread.
    pub fn run(&self, node: &Arc<Node>) {
        loop {
            let event = node.wait_next_event();

            let mut delivered = false;
            if let Some(hash) = Self::payment_hash_of(&event) {
                let waiters = self.waiters.lock().unwrap();
                if let Some(sender) = waiters.get(&hash) {
                    let _ = sender.send(event.clone());
                    delivered = true;
                }
            }

            if !delivered {
                let role = self.role.lock().unwrap().clone();
                self.emitter.emit(
                    &role,
                    "LDK_EVENT",
                    serde_json::json!({
                        "event": format!("{:?}", event),
                    }),
                );
            }

            node.event_handled().expect("event_handled failed");
        }
    }
}
