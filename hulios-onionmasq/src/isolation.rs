use futures::channel::mpsc::UnboundedSender;
use once_cell::sync::Lazy;
use onionmasq::scaffolding::TunnelCommand;
use onionmasq::CountryCode;
use onionmasq::IpEndpoint;
use onionmasq::TunnelScaffolding;
use std::io;
use std::sync::Mutex;

static COMMAND_SENDER: Lazy<Mutex<Option<UnboundedSender<TunnelCommand>>>> =
    Lazy::new(|| Mutex::new(None));

pub mod hulios_state {
    pub mod watchdog {
        use std::sync::OnceLock;
        pub static CLEAR_IP_CACHE: OnceLock<fn()> = OnceLock::new();
        pub fn clear_ip_cache() {
            if let Some(cb) = CLEAR_IP_CACHE.get() {
                cb();
            }
        }
    }
}

pub fn trigger_new_circuit() {
    if let Some(sender) = COMMAND_SENDER.lock().unwrap().as_mut() {
        let _ = sender.unbounded_send(TunnelCommand::RefreshCircuits);
        // Clear cached IP in watchdog
        hulios_state::watchdog::clear_ip_cache();
    }
}

pub struct HuliosScaffolding {
    pub exit_country: Option<String>,
}

impl TunnelScaffolding for HuliosScaffolding {
    fn isolate(&self, _src: IpEndpoint, _dst: IpEndpoint, _ip_proto: u8) -> io::Result<u64> {
        Ok(0)
    }

    fn command_stream(
        &self,
    ) -> Option<Box<dyn futures::Stream<Item = TunnelCommand> + Send + Sync>> {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        *COMMAND_SENDER.lock().unwrap() = Some(tx);
        Some(Box::new(rx))
    }

    fn locate(
        &self,
        _src: IpEndpoint,
        _dst: IpEndpoint,
        _isolation_key: u64,
    ) -> Option<CountryCode> {
        if let Some(ref cc) = self.exit_country {
            match cc.parse::<CountryCode>() {
                Ok(country) => Some(country),
                Err(err) => {
                    tracing::warn!("Failed to parse exit country '{}': {:?}", cc, err);
                    None
                }
            }
        } else {
            None
        }
    }
}
