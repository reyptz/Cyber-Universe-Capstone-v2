use anyhow::Result;
use async_trait::async_trait;
use crate::events::SecurityEvent;

/// Trait for eBPF sensors
#[async_trait]
pub trait Sensor: Send + Sync {
    fn name(&self) -> &str;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self);
}

/// Example sensor implementation placeholder
pub struct ProcessExecSensor {
    pub running: bool,
}

impl ProcessExecSensor {
    pub fn new() -> Self {
        ProcessExecSensor { running: false }
    }
}

#[async_trait]
impl Sensor for ProcessExecSensor {
    fn name(&self) -> &str {
        "ProcessExecSensor"
    }

    async fn start(&mut self) -> Result<()> {
        self.running = true;
        Ok(())
    }

    async fn stop(&mut self) {
        self.running = false;
    }
}
