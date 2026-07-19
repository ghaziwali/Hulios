mod cgroup;
mod diagnostics;
mod dirty_state;
mod errors;
mod loader;
mod operations;
mod snapshot;
mod status;
mod time_sync;
mod types;
pub mod watchdog;

pub use cgroup::{detect_cgroup_path_state, get_cgroup_path};
pub use diagnostics::*;
pub use dirty_state::detect_dirty_state;
pub use errors::*;
pub use operations::*;
pub use snapshot::{detect_phys_iface, take_routing_snapshot, RoutingSnapshot};
pub use status::display_status;
pub use time_sync::run_time_sync;
pub use types::*;
pub use watchdog::ControlRequest;

use std::sync::{Mutex, OnceLock};

pub use hulios_cli::{HuliosConfig, PrivilegeCallback};

static ACTIVE_HANDLES: OnceLock<Mutex<Option<ActiveHandles>>> = OnceLock::new();

pub(crate) fn get_active_handles() -> &'static Mutex<Option<ActiveHandles>> {
    ACTIVE_HANDLES.get_or_init(|| Mutex::new(None))
}

pub fn read_strict_lockdown_from_state() -> bool {
    let state_path = get_state_toml_path();
    if state_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&state_path) {
            if let Ok(state) = toml::from_str::<RunningState>(&content) {
                return state.strict_lockdown;
            }
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use tempfile::TempDir;

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn get_test_lock() -> &'static Mutex<()> {
        TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn setup_env(temp_dir: &TempDir) {
        let run_dir = temp_dir.path().join("run");
        let sys_dir = temp_dir.path().join("sys");
        let etc_dir = temp_dir.path().join("etc");
        let udev_dir = temp_dir.path().join("udev");

        fs::create_dir_all(&run_dir).unwrap();
        fs::create_dir_all(&sys_dir).unwrap();
        fs::create_dir_all(&etc_dir).unwrap();
        fs::create_dir_all(&udev_dir).unwrap();

        std::env::set_var("HULIOS_STATE_TOML_PATH", run_dir.join("state.toml"));
        std::env::set_var("HULIOS_CGROUP_DIR_PATH", sys_dir.join("cgroup"));
        std::env::set_var("HULIOS_RESOLV_CONF_PATH", etc_dir.join("resolv.conf"));
        std::env::set_var("HULIOS_TUN_CLASS_PATH", sys_dir.join("hulios0"));
        std::env::set_var(
            "HULIOS_ROUTING_SNAPSHOT_PATH",
            run_dir.join("routing_snapshot.toml"),
        );
        std::env::set_var("HULIOS_BPF_PIN_DIR_PATH", sys_dir.join("bpf"));
        std::env::set_var("HULIOS_VAR_LIB_PATH", run_dir.join("var_lib_arti"));
        std::env::set_var("HULIOS_MOCK_IP_RULES", "false");
        std::env::set_var("HULIOS_MOCK_RECOVERY", "true");
        std::env::set_var("HULIOS_MOCK_EBPF", "true");
        std::env::set_var("HULIOS_MOCK_ARTI", "true");
        std::env::set_var("HULIOS_MOCK_CAPS", "true");
        std::env::set_var("HULIOS_MOCK_TIME_SYNC", "pass");
        std::env::set_var("HULIOS_CONTROL_SOCK_PATH", run_dir.join("control.sock"));
        std::env::set_var(
            "HULIOS_UDEV_RULES_PATH",
            udev_dir.join("99-hulios-unmanaged.rules"),
        );
        println!(
            "DEBUG_SETUP: HULIOS_MOCK_EBPF is set to {:?}",
            std::env::var("HULIOS_MOCK_EBPF")
        );
    }

    fn teardown_env() {
        std::env::remove_var("HULIOS_STATE_TOML_PATH");
        std::env::remove_var("HULIOS_CGROUP_DIR_PATH");
        std::env::remove_var("HULIOS_RESOLV_CONF_PATH");
        std::env::remove_var("HULIOS_TUN_CLASS_PATH");
        std::env::remove_var("HULIOS_ROUTING_SNAPSHOT_PATH");
        std::env::remove_var("HULIOS_BPF_PIN_DIR_PATH");
        std::env::remove_var("HULIOS_VAR_LIB_PATH");
        std::env::remove_var("HULIOS_MOCK_IP_RULES");
        std::env::remove_var("HULIOS_MOCK_RECOVERY");
        std::env::remove_var("HULIOS_MOCK_EBPF");
        std::env::remove_var("HULIOS_MOCK_ARTI");
        std::env::remove_var("HULIOS_MOCK_CAPS");
        std::env::remove_var("HULIOS_MOCK_TIME_SYNC");
        std::env::remove_var("HULIOS_FAIL_PHASE");
        std::env::remove_var("HULIOS_CONTROL_SOCK_PATH");
        std::env::remove_var("HULIOS_UDEV_RULES_PATH");
    }

    #[tokio::test]
    async fn test_clean_system_not_dirty() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        let report = detect_dirty_state().await;
        assert!(!report.is_dirty());
        assert_eq!(
            report,
            DirtyStateReport {
                stale_rules: false,
                stale_cgroup: false,
                stale_tun_interface: false,
                stale_state_file: false,
                stale_bpf: false,
            }
        );

        teardown_env();
    }

    #[tokio::test]
    async fn test_dirty_state_detection_and_recovery() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        // 1. Simulate dirty state
        std::env::set_var("HULIOS_MOCK_IP_RULES", "true");

        // Create cgroup dir
        let cgroup_dir = get_cgroup_dir_path();
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::write(cgroup_dir.join("cgroup.procs"), "").unwrap(); // Empty procs -> stale

        // Create tun interface dir
        let tun_class = get_tun_class_path("hulios0");
        fs::create_dir_all(&tun_class).unwrap();

        // Create BPF pin dir and a dummy pinned program
        let bpf_pin_dir = get_bpf_pin_dir_path();
        fs::create_dir_all(&bpf_pin_dir).unwrap();
        fs::write(bpf_pin_dir.join("sock_ops"), "dummy bpf link").unwrap();

        let report = detect_dirty_state().await;
        assert!(report.is_dirty());
        assert!(report.stale_rules);
        assert!(report.stale_cgroup);
        assert!(report.stale_tun_interface);
        assert!(!report.stale_state_file);
        assert!(report.stale_bpf);

        // 3. Recover
        recover().await.unwrap();

        // 4. Verify cgroup, BPF pin, and tun dirs are removed (via mock recovery)
        assert!(!cgroup_dir.exists());
        assert!(!tun_class.exists());
        assert!(!bpf_pin_dir.exists());

        // 5. Detect again to verify clean
        std::env::set_var("HULIOS_MOCK_IP_RULES", "false");
        let report_clean = detect_dirty_state().await;
        assert!(!report_clean.is_dirty());

        // 6. Test Idempotency
        recover().await.unwrap();
        let report_again = detect_dirty_state().await;
        assert!(!report_again.is_dirty());

        teardown_env();
    }

    #[tokio::test]
    async fn test_dirty_state_last_signal() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        // 1. Simulate state file with "running"
        let state_path = get_state_toml_path();
        let state = RunningState {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            last_signal: "running".to_string(),
            saved_sysctls: None,
            avahi_saved: None,
            ntp_was_enabled: None,
            strict_lockdown: false,
            ipv6: None,
        };
        let state_str = toml::to_string(&state).unwrap();
        fs::write(&state_path, state_str).unwrap();

        // 2. Detect
        let report = detect_dirty_state().await;
        assert!(report.is_dirty());
        assert!(report.stale_state_file);

        // 3. Recover
        recover().await.unwrap();

        // 4. Verify state file is deleted
        assert!(!state_path.exists());

        // 5. Detect again to verify clean
        let report_clean = detect_dirty_state().await;
        assert!(!report_clean.is_dirty());

        teardown_env();
    }

    #[tokio::test]
    async fn test_startup_full_success() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        let cfg = HuliosConfig {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            ..Default::default()
        };

        let state = startup(cfg).await.unwrap();
        assert_eq!(state.fwmark, 12345);
        assert_eq!(state.tun_name, "hulios0");
        assert_eq!(state.last_signal, "running");

        // Verify state file is written
        let state_path = get_state_toml_path();
        assert!(state_path.exists());

        teardown_env();
    }

    #[tokio::test]
    async fn test_startup_phase_9_failure_and_rollback() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        // Fail at HardenSystem (Phase 9)
        std::env::set_var("HULIOS_FAIL_PHASE", "HardenSystem");

        let cfg = HuliosConfig {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            ..Default::default()
        };

        let start_res = startup(cfg).await;
        assert!(start_res.is_err());

        // Trigger recovery to perform cleanup
        crate::operations::recover().await.unwrap();

        // Verify that preceding steps were rolled back:
        // - State file should NOT exist
        assert!(!get_state_toml_path().exists());
        // - TUN interface dir (created in step 5) should be deleted
        assert!(!get_tun_class_path("hulios0").exists());
        // - Routing snapshot should be deleted
        assert!(!get_routing_snapshot_path().exists());

        teardown_env();
    }

    #[tokio::test]
    async fn test_teardown_normal() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        let cfg = HuliosConfig {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            ..Default::default()
        };

        let state = startup(cfg).await.unwrap();
        assert!(get_state_toml_path().exists());

        teardown(state, TeardownMode::Normal).await.unwrap();
        assert!(!get_state_toml_path().exists());

        teardown_env();
    }

    #[tokio::test]
    async fn test_teardown_strict_lockdown() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        let cfg = HuliosConfig {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            ..Default::default()
        };

        let state = startup(cfg).await.unwrap();
        assert!(get_state_toml_path().exists());

        teardown(state, TeardownMode::StrictLockdown).await.unwrap();
        assert!(!get_state_toml_path().exists());

        teardown_env();
    }

    #[tokio::test]
    async fn test_status_not_running() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        // State file is absent, display_status should fail
        let res = display_status().await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "Hulios is not running");

        // Now write state file but keep socket absent
        let state_path = get_state_toml_path();
        let state = RunningState {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            last_signal: "running".to_string(),
            saved_sysctls: None,
            avahi_saved: None,
            ntp_was_enabled: None,
            strict_lockdown: false,
            ipv6: None,
        };
        fs::write(&state_path, toml::to_string(&state).unwrap()).unwrap();

        let sock_path = temp.path().join("run").join("control.sock");
        std::env::set_var("HULIOS_CONTROL_SOCK_PATH", &sock_path);

        let res = display_status().await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "Hulios is not running");

        teardown_env();
        std::env::remove_var("HULIOS_CONTROL_SOCK_PATH");
    }

    #[tokio::test]
    async fn test_status_running() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        let state_path = get_state_toml_path();
        let state = RunningState {
            fwmark: 12345,
            tun_name: "hulios0".to_string(),
            last_signal: "running".to_string(),
            saved_sysctls: None,
            avahi_saved: None,
            ntp_was_enabled: None,
            strict_lockdown: false,
            ipv6: None,
        };
        fs::write(&state_path, toml::to_string(&state).unwrap()).unwrap();

        let sock_path = temp.path().join("run").join("control.sock");
        std::env::set_var("HULIOS_CONTROL_SOCK_PATH", &sock_path);

        // Start a mock Unix socket listener
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok() {
                    let response = serde_json::json!({
                        "bootstrap": 100,
                        "circuits": 5,
                        "consensus_age_secs": 120,
                        "exit_ip": "1.2.3.4",
                        "uptime_secs": 65
                    });
                    let resp_str = format!("{}\n", response);
                    let _ = stream.write_all(resp_str.as_bytes()).await;
                }
            }
        });

        let res = display_status().await;
        assert!(res.is_ok());

        handle.await.unwrap();

        teardown_env();
        std::env::remove_var("HULIOS_CONTROL_SOCK_PATH");
    }

    #[tokio::test]
    async fn test_control_socket_server_real() {
        let _lock = get_test_lock().lock().unwrap();
        std::env::set_var("HULIOS_MOCK_TIME_SYNC", "pass");
        let temp = TempDir::new().unwrap();
        let run_dir = temp.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let sock_path = run_dir.join("control_real.sock");

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let start_time = std::time::SystemTime::now();

        // Spawn the control socket server loop
        let server_task = tokio::spawn(watchdog::run_control_socket(
            listener, None, // No arti_client
            None, // No status_handle
            start_time,
        ));

        // Connect to it
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(&sock_path).await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // Command 1: status
        write_half
            .write_all(b"{\"cmd\":\"status\"}\n")
            .await
            .unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        let status: StatusResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(status.bootstrap, 0);
        assert_eq!(status.circuits, 0);

        // Command 2: new-circuit
        write_half
            .write_all(b"{\"cmd\":\"new-circuit\",\"cgroup\":999}\n")
            .await
            .unwrap();
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        let new_circ_resp: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(new_circ_resp["status"], "ok");

        // Command 3: time-sync
        write_half
            .write_all(b"{\"cmd\":\"time-sync\"}\n")
            .await
            .unwrap();
        response.clear();
        reader.read_line(&mut response).await.unwrap();
        let time_sync_resp: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(time_sync_resp["status"], "ok");

        server_task.abort();
        std::env::remove_var("HULIOS_MOCK_TIME_SYNC");
    }

    #[tokio::test]
    async fn test_diagnose_success() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let run_dir = temp.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let sock_path = run_dir.join("control.sock");

        let state_path = run_dir.join("state.toml");
        std::fs::write(
            &state_path,
            "fwmark = 12345\ntun_name = \"hulios0\"\nlast_signal = \"running\"\n",
        )
        .unwrap();

        let udev_dir = temp.path().join("udev");
        std::fs::create_dir_all(&udev_dir).unwrap();
        let udev_rules_path = udev_dir.join("99-hulios-unmanaged.rules");
        std::fs::write(&udev_rules_path, "").unwrap();

        std::env::set_var("HULIOS_STATE_TOML_PATH", &state_path);
        std::env::set_var("HULIOS_CONTROL_SOCK_PATH", &sock_path);
        std::env::set_var("HULIOS_UDEV_RULES_PATH", &udev_rules_path);
        std::env::set_var("HULIOS_MOCK_IP_RULES", "pass");
        std::env::set_var("HULIOS_MOCK_IP_ROUTES", "pass");
        std::env::set_var("HULIOS_MOCK_DNS_RESOLUTION", "pass");
        std::env::set_var("HULIOS_MOCK_EBPF", "pass");
        std::env::set_var("HULIOS_MOCK_LEAK_TEST", "pass");

        // Spawn mock control socket server
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let start_time = std::time::SystemTime::now();
        let server_task = tokio::spawn(watchdog::run_control_socket(
            listener, None, None, start_time,
        ));

        let res = run_diagnose(false).await;
        assert!(res.is_ok());

        server_task.abort();
        teardown_env();
        std::env::remove_var("HULIOS_STATE_TOML_PATH");
        std::env::remove_var("HULIOS_CONTROL_SOCK_PATH");
        std::env::remove_var("HULIOS_MOCK_IP_RULES");
        std::env::remove_var("HULIOS_MOCK_IP_ROUTES");
        std::env::remove_var("HULIOS_MOCK_DNS_RESOLUTION");
        std::env::remove_var("HULIOS_MOCK_EBPF");
        std::env::remove_var("HULIOS_MOCK_LEAK_TEST");
    }

    #[tokio::test]
    async fn test_diagnose_failures() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let run_dir = temp.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let sock_path = run_dir.join("control.sock");

        let state_path = run_dir.join("state.toml");
        std::fs::write(
            &state_path,
            "fwmark = 12345\ntun_name = \"hulios0\"\nlast_signal = \"running\"\n",
        )
        .unwrap();

        let udev_dir = temp.path().join("udev");
        std::fs::create_dir_all(&udev_dir).unwrap();
        let udev_rules_path = udev_dir.join("99-hulios-unmanaged.rules");
        std::fs::write(&udev_rules_path, "").unwrap();

        std::env::set_var("HULIOS_STATE_TOML_PATH", &state_path);
        std::env::set_var("HULIOS_CONTROL_SOCK_PATH", &sock_path);
        std::env::set_var("HULIOS_UDEV_RULES_PATH", &udev_rules_path);

        // Mock routing rules to fail
        std::env::set_var("HULIOS_MOCK_IP_RULES", "fail");
        std::env::set_var("HULIOS_MOCK_IP_ROUTES", "pass");
        std::env::set_var("HULIOS_MOCK_DNS_RESOLUTION", "pass");
        std::env::set_var("HULIOS_MOCK_EBPF", "pass");
        std::env::set_var("HULIOS_MOCK_LEAK_TEST", "pass");

        // Spawn mock control socket server
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let start_time = std::time::SystemTime::now();
        let server_task = tokio::spawn(watchdog::run_control_socket(
            listener, None, None, start_time,
        ));

        let res = run_diagnose(false).await;
        assert!(res.is_err());

        server_task.abort();
        teardown_env();
        std::env::remove_var("HULIOS_STATE_TOML_PATH");
        std::env::remove_var("HULIOS_CONTROL_SOCK_PATH");
        std::env::remove_var("HULIOS_MOCK_IP_RULES");
        std::env::remove_var("HULIOS_MOCK_IP_ROUTES");
        std::env::remove_var("HULIOS_MOCK_DNS_RESOLUTION");
        std::env::remove_var("HULIOS_MOCK_EBPF");
        std::env::remove_var("HULIOS_MOCK_LEAK_TEST");
    }

    #[tokio::test]
    async fn test_time_sync_consensus() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let arti_dir = temp.path().join("arti");
        let cache_dir = arti_dir.join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let consensus_content = "\
valid-after 2026-06-18 00:00:00
fresh-until 2026-06-18 01:00:00
valid-until 2026-06-18 03:00:00
";
        let consensus_file = cache_dir.join("cached-consensus");
        std::fs::write(&consensus_file, consensus_content).unwrap();

        std::env::set_var("HULIOS_ARTI_DIR_PATH", &arti_dir);
        std::env::set_var("HULIOS_MOCK_TIME_SYNC", "clock_only");

        let res = run_time_sync(hulios_cli::TimeSyncMode::Consensus, None).await;
        assert!(res.is_ok());

        std::env::remove_var("HULIOS_ARTI_DIR_PATH");
        std::env::remove_var("HULIOS_MOCK_TIME_SYNC");
    }

    #[tokio::test]
    async fn test_startup_exit_country_code_validation() {
        let _lock = get_test_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        setup_env(&temp);

        // Test valid country code (2 ASCII alphabetic)
        let cfg_valid = HuliosConfig {
            exit_nodes: Some("us".to_string()),
            ..Default::default()
        };
        let start_res = startup(cfg_valid).await;
        assert!(start_res.is_ok());

        // Test invalid country code (too long)
        let cfg_invalid_long = HuliosConfig {
            exit_nodes: Some("usa".to_string()),
            ..Default::default()
        };
        let start_res = startup(cfg_invalid_long).await;
        assert!(start_res.is_err());
        assert!(start_res
            .unwrap_err()
            .to_string()
            .contains("Invalid exit country code 'usa'"));

        // Test invalid country code (non-alphabetic)
        let cfg_invalid_num = HuliosConfig {
            exit_nodes: Some("u1".to_string()),
            ..Default::default()
        };
        let start_res = startup(cfg_invalid_num).await;
        assert!(start_res.is_err());
        assert!(start_res
            .unwrap_err()
            .to_string()
            .contains("Invalid exit country code 'u1'"));

        teardown_env();
    }
}
