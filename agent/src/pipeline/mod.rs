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

    pub fn pop(&mut self) -> Option<AgentEvent> {
        self.inner.pop_front()
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new()
    }
}
