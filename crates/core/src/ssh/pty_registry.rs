//! Registry of live PTY sessions, keyed by connection id.
//!
//! Owns the two pieces of PTY bookkeeping that previously lived directly on
//! `ConnectionManager`: the session map and the per-connection generation
//! counter. The generation counter guards against a stale `Close` killing a
//! newly created session: every `insert` bumps the connection's generation,
//! and `remove` with an expected generation is a no-op when the counter has
//! moved on.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use super::PtySession;

#[derive(Default)]
pub(crate) struct PtyRegistry {
    sessions: RwLock<HashMap<String, Arc<PtySession>>>,
    /// Generation counter per connection id — incremented on each insert.
    generations: RwLock<HashMap<String, u64>>,
}

impl PtyRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Cancel and remove any existing session for `connection_id` without
    /// touching the generation counter. Called before creating a replacement
    /// session so the old SSH channel and reader task are torn down first,
    /// preventing orphaned sessions.
    pub(crate) async fn cancel_existing(&self, connection_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(old_session) = sessions.remove(connection_id) {
            old_session.cancel.cancel();
            tracing::info!("Cancelled old PTY session for {}", connection_id);
        }
    }

    /// Register a new session for `connection_id`, bumping and returning the
    /// connection's generation so any in-flight Close for the old session is
    /// ignored.
    pub(crate) async fn insert(&self, connection_id: &str, session: PtySession) -> u64 {
        let current_gen = {
            let mut generations = self.generations.write().await;
            let entry = generations.entry(connection_id.to_string()).or_insert(0);
            *entry += 1;
            *entry
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(connection_id.to_string(), Arc::new(session));

        current_gen
    }

    pub(crate) async fn get(&self, connection_id: &str) -> Option<Arc<PtySession>> {
        self.sessions.read().await.get(connection_id).cloned()
    }

    pub(crate) async fn cancel_token(&self, connection_id: &str) -> Option<CancellationToken> {
        self.sessions
            .read()
            .await
            .get(connection_id)
            .map(|s| s.cancel.clone())
    }

    /// Cancel and remove the session for `connection_id`, but only if
    /// `expected_gen` matches the current generation (pass `None` to remove
    /// unconditionally). A mismatch means the Close is stale — a newer
    /// session has since been created — and is ignored.
    pub(crate) async fn remove(&self, connection_id: &str, expected_gen: Option<u64>) {
        if let Some(expected_generation) = expected_gen {
            let generations = self.generations.read().await;
            let current_gen = generations.get(connection_id).copied().unwrap_or(0);
            if current_gen != expected_generation {
                tracing::info!(
                    "Ignoring stale Close for {} (gen {} != current {})",
                    connection_id,
                    expected_generation,
                    current_gen
                );
                return;
            }
        }
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(connection_id) {
            session.cancel.cancel();
        }
    }

    /// Tear down all PTY state for `connection_id`, including the generation
    /// counter, so nothing leaks across reconnects. Used when the owning SSH
    /// connection is closed.
    pub(crate) async fn purge(&self, connection_id: &str) {
        {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.remove(connection_id) {
                session.cancel.cancel();
            }
        }
        let mut generations = self.generations.write().await;
        generations.remove(connection_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn test_session() -> (PtySession, CancellationToken) {
        let (input_tx, _input_rx) = mpsc::channel(4);
        let (_output_tx, output_rx) = mpsc::channel(4);
        let (resize_tx, _resize_rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let session = PtySession {
            input_tx,
            output_rx: Arc::new(tokio::sync::Mutex::new(output_rx)),
            resize_tx,
            cancel: cancel.clone(),
        };
        (session, cancel)
    }

    #[tokio::test]
    async fn insert_bumps_generation_per_connection() {
        let registry = PtyRegistry::new();
        let (s1, _) = test_session();
        let (s2, _) = test_session();
        let (other, _) = test_session();

        assert_eq!(registry.insert("conn-a", s1).await, 1);
        assert_eq!(registry.insert("conn-a", s2).await, 2);
        assert_eq!(registry.insert("conn-b", other).await, 1);
    }

    #[tokio::test]
    async fn stale_close_is_ignored_but_matching_close_cancels() {
        let registry = PtyRegistry::new();
        let (s1, cancel1) = test_session();
        let gen1 = registry.insert("conn", s1).await;

        // A newer session replaces the first.
        let (s2, cancel2) = test_session();
        let gen2 = registry.insert("conn", s2).await;
        assert_ne!(gen1, gen2);

        // Close targeting the old generation must not touch the new session.
        registry.remove("conn", Some(gen1)).await;
        assert!(registry.get("conn").await.is_some());
        assert!(!cancel2.is_cancelled());

        // Close with the current generation tears it down.
        registry.remove("conn", Some(gen2)).await;
        assert!(registry.get("conn").await.is_none());
        assert!(cancel2.is_cancelled());
        // The first session was never cancelled via remove (it was simply
        // replaced without cancel_existing in this test).
        assert!(!cancel1.is_cancelled());
    }

    #[tokio::test]
    async fn cancel_existing_cancels_and_removes_without_bumping_generation() {
        let registry = PtyRegistry::new();
        let (s1, cancel1) = test_session();
        registry.insert("conn", s1).await;

        registry.cancel_existing("conn").await;
        assert!(cancel1.is_cancelled());
        assert!(registry.get("conn").await.is_none());

        // Next insert continues the generation sequence.
        let (s2, _) = test_session();
        assert_eq!(registry.insert("conn", s2).await, 2);
    }

    #[tokio::test]
    async fn purge_resets_generation_counter() {
        let registry = PtyRegistry::new();
        let (s1, cancel1) = test_session();
        registry.insert("conn", s1).await;

        registry.purge("conn").await;
        assert!(cancel1.is_cancelled());
        assert!(registry.get("conn").await.is_none());

        // Generation restarts after a purge (no leak across reconnects).
        let (s2, _) = test_session();
        assert_eq!(registry.insert("conn", s2).await, 1);
    }

    #[tokio::test]
    async fn unconditional_remove_of_unknown_id_is_noop() {
        let registry = PtyRegistry::new();
        registry.remove("ghost", None).await;
        registry.purge("ghost").await;
        assert!(registry.get("ghost").await.is_none());
        assert!(registry.cancel_token("ghost").await.is_none());
    }
}
