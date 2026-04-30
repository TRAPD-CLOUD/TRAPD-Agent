use std::collections::VecDeque;

use tokio::sync::mpsc;

use crate::schema::AgentEvent;

pub const CHANNEL_CAPACITY: usize = 1_000;
pub const RING_BUFFER_MAX: usize = 10_000;

pub fn create_pipeline() -> (mpsc::Sender<AgentEvent>, mpsc::Receiver<AgentEvent>) {
    mpsc::channel(CHANNEL_CAPACITY)
}

pub struct RingBuffer {
    inner: VecDeque<AgentEvent>,
    max:   usize,
}

impl RingBuffer {
    pub fn new() -> Self {
        Self {
            inner: VecDeque::with_capacity(RING_BUFFER_MAX),
            max:   RING_BUFFER_MAX,
        }
    }

    pub fn push(&mut self, event: AgentEvent) {
        if self.inner.len() >= self.max {
            self.inner.pop_front();
            tracing::warn!("Ring buffer full — dropped oldest event");
        }
        self.inner.push_back(event);
    }

    /// Returns up to `n` events from the front without removing them.
    pub fn peek_batch(&self, n: usize) -> Vec<AgentEvent> {
        self.inner.iter().take(n).cloned().collect()
    }

    /// Removes the first `n` events from the front.
    pub fn drain(&mut self, n: usize) {
        let count = n.min(self.inner.len());
        self.inner.drain(..count);
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl RingBuffer {
    pub fn with_max(max: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            max,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests;
