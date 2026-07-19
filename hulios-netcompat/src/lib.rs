mod conflict;
mod iwd;
mod network_manager;
mod systemd;

pub use conflict::{detect_vpn_fwmark_conflict, ConflictInfo};
pub use network_manager::{
    install_nm_dispatcher, remove_nm_dispatcher, remove_nm_unmanaged_conf, write_nm_unmanaged_conf,
    write_nm_unmanaged_conf_ex,
};
pub use systemd::{restore_avahi, suppress_avahi, SavedSystemdServices};

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static SERIAL_TEST: Mutex<()> = Mutex::new(());

    fn create_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("hulios-test-{}", nanos));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn test_nm_and_avahi_suppression() {
        let _guard = SERIAL_TEST.lock().unwrap();
        let test_dir = create_temp_dir();
        let bin_dir = test_dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();

        let nm_conf_path = test_dir.join("99-hulios-unmanaged.conf");
        let log_path = test_dir.join("log.txt");
        let avahi_state_path = test_dir.join("avahi_state.txt");

        // Write mock nmcli command
        let nmcli_script = format!(
            "#!/bin/sh\necho \"nmcli $*\" >> \"{}\"\nexit 0\n",
            log_path.to_string_lossy()
        );
        let nmcli_path = bin_dir.join("nmcli");
        fs::write(&nmcli_path, nmcli_script).unwrap();

        // Write mock systemctl command
        let systemctl_script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then\n  cat \"{}\"\n  exit 0\nfi\necho \"systemctl $*\" >> \"{}\"\nexit 0\n",
            avahi_state_path.to_string_lossy(),
            log_path.to_string_lossy()
        );
        let systemctl_path = bin_dir.join("systemctl");
        fs::write(&systemctl_path, systemctl_script).unwrap();

        // Make mock scripts executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in &[&nmcli_path, &systemctl_path] {
                let mut perms = fs::metadata(path).unwrap().permissions();
                perms.set_mode(0o755);
                fs::set_permissions(path, perms).unwrap();
            }
        }

        // Set environment variables for test execution
        env::set_var("HULIOS_NM_CONF_PATH", nm_conf_path.to_str().unwrap());
        env::set_var("HULIOS_FORCE_SYSTEMCTL", "true");

        let path_env = env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.to_str().unwrap(), path_env);
        env::set_var("PATH", new_path);

        // 1. Test write_nm_unmanaged_conf
        write_nm_unmanaged_conf("hulios0").await.unwrap();
        assert!(nm_conf_path.exists());
        let content = fs::read_to_string(&nm_conf_path).unwrap();
        assert!(content.contains("unmanaged-devices=interface-name:hulios0"));
        assert!(content.contains("enabled=false"));

        // Check nmcli reload was logged
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(log_content.contains("nmcli general reload"));

        // Clear log
        fs::write(&log_path, "").unwrap();

        // 2. Test suppress_avahi when avahi is inactive
        fs::write(&avahi_state_path, "inactive").unwrap();
        let saved = suppress_avahi().await.unwrap();
        assert!(!saved.avahi_was_active);
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(!log_content.contains("systemctl stop"));

        // Clear log
        fs::write(&log_path, "").unwrap();

        // 3. Test suppress_avahi when avahi is active
        fs::write(&avahi_state_path, "active").unwrap();
        let saved_active = suppress_avahi().await.unwrap();
        assert!(saved_active.avahi_was_active);
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(log_content.contains("systemctl stop avahi-daemon.service"));

        // Clear log
        fs::write(&log_path, "").unwrap();

        // 4. Test restore_avahi when it was active
        restore_avahi(&saved_active).await.unwrap();
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(log_content.contains("systemctl start avahi-daemon.service"));

        // Clear log
        fs::write(&log_path, "").unwrap();

        // 5. Test restore_avahi when it was inactive
        restore_avahi(&saved).await.unwrap();
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(!log_content.contains("systemctl start avahi-daemon.service"));

        // Clear log
        fs::write(&log_path, "").unwrap();

        // 6. Test remove_nm_unmanaged_conf
        remove_nm_unmanaged_conf().await.unwrap();
        assert!(!nm_conf_path.exists());
        let log_content = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(log_content.contains("nmcli general reload"));

        // Clean up environment variables
        env::remove_var("HULIOS_NM_CONF_PATH");
        env::remove_var("HULIOS_FORCE_SYSTEMCTL");
        env::set_var("PATH", path_env);

        // Clean up files
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn test_nm_dispatcher_installation() {
        let _guard = SERIAL_TEST.lock().unwrap();
        let test_dir = create_temp_dir();
        let dispatcher_path = test_dir.join("99-hulios");

        env::set_var(
            "HULIOS_NM_DISPATCHER_PATH",
            dispatcher_path.to_str().unwrap(),
        );

        // 1. Install dispatcher
        install_nm_dispatcher(42, "hulios0", true).await.unwrap();
        assert!(dispatcher_path.exists());

        // Verify contents
        let content = fs::read_to_string(&dispatcher_path).unwrap();
        assert!(content.contains("ip rule show | grep -q \"fwmark 0x2a\""));
        assert!(content.contains("ip rule add fwmark 42"));

        // Verify permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&dispatcher_path).unwrap();
            let mode = metadata.permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }

        // 2. Remove dispatcher
        remove_nm_dispatcher().await.unwrap();
        assert!(!dispatcher_path.exists());

        env::remove_var("HULIOS_NM_DISPATCHER_PATH");
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn test_detect_vpn_fwmark_conflict() {
        let _guard = SERIAL_TEST.lock().unwrap();
        let temp = create_temp_dir();
        env::set_var("HULIOS_WG_CONF_DIR", temp.to_str().unwrap());

        // 1. Write a conflict config with decimal mark
        let conf1 = temp.join("wg0.conf");
        fs::write(&conf1, "[Interface]\nFwMark = 12345\n").unwrap();

        let res = detect_vpn_fwmark_conflict(12345).await.unwrap();
        assert!(res.is_some());
        let info = res.unwrap();
        assert_eq!(info.existing_mark, 12345);
        assert!(info.rule_description.contains("wg0.conf"));

        // 2. Write a conflict config with hex mark
        let conf2 = temp.join("wg1.conf");
        fs::write(&conf2, "[Interface]\nFwMark = 0x3039\n").unwrap();

        let res2 = detect_vpn_fwmark_conflict(12345).await.unwrap();
        assert!(res2.is_some());

        // 3. Test non-conflicting mark
        let res3 = detect_vpn_fwmark_conflict(9999).await.unwrap();
        assert!(res3.is_none());

        // 4. Test mocked netlink conflict
        env::set_var("HULIOS_MOCK_NETLINK_CONFLICT", "true");
        let res4 = detect_vpn_fwmark_conflict(9999).await.unwrap();
        assert!(res4.is_some());
        assert_eq!(res4.unwrap().existing_mark, 9999);
        env::remove_var("HULIOS_MOCK_NETLINK_CONFLICT");

        env::remove_var("HULIOS_WG_CONF_DIR");
        let _ = fs::remove_dir_all(&temp);
    }
}
