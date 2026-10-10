//! Host services are injected by the executable; independent engines need no agent modules.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Clone, Default)]
pub struct Paths {
    pub iocs: Option<PathBuf>,
    pub sigma: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
}
pub trait Runtime: Send + Sync {
    fn detection_uncatalogued(&self) {}
    fn detection_suppressed(&self) {}
    fn detection_aggregated(&self) {}
    fn shadow_hit(&self, _rule_id: &str) {}
    fn write_baseline(&self, _path: &Path, _bytes: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("baseline persistence requires a host adapter")
    }
}
pub struct NoopRuntime;
impl Runtime for NoopRuntime {}
pub fn noop() -> Arc<dyn Runtime> {
    Arc::new(NoopRuntime)
}
