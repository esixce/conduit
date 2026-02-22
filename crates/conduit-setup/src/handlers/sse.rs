use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::Json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::events::*;
use crate::state::*;

pub async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.emitter.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        result.ok().map(|event| {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Ok::<_, Infallible>(SseEvent::default().id(event.id.to_string()).data(json))
        })
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}


/// GET /api/events/history -- paginated event log (since_id, limit, role)
pub async fn events_history_handler(
    State(state): State<AppState>,
    Query(q): Query<EventsHistoryQuery>,
) -> Json<Vec<ConsoleEvent>> {
    let since_id = q.since_id.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).min(1000);
    let role = q.role.as_deref();
    let events = state
        .emitter
        .event_log()
        .and_then(|log| log.query(since_id, limit, role).ok())
        .unwrap_or_default();
    Json(events)
}


