use crate::types::{DirtyStateReport, RunningState};

fn has_pinned_bpf_programs() -> bool {
    let path = crate::types::get_bpf_pin_dir_path();
    if !path.exists() {
        return false;
    }
    if let Ok(entries) = std::fs::read_dir(&path) {
        entries.filter_map(Result::ok).next().is_some()
    } else {
        false
    }
}

pub async fn detect_dirty_state() -> DirtyStateReport {
    let mut fwmark = hulios_common::HULIOS_FWMARK;
    let mut tun_name = "hulios0".to_string();
    let mut stale_state_file = false;
    let state_path = crate::types::get_state_toml_path();
    if state_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&state_path) {
            if let Ok(state) = toml::from_str::<RunningState>(&content) {
                fwmark = state.fwmark;
                tun_name = state.tun_name.clone();
                if state.last_signal == "running" {
                    stale_state_file = true;
                }
            }
        }
    }

    let stale_rules = crate::snapshot::has_stale_rules(fwmark).await;
    let stale_cgroup = crate::cgroup::is_cgroup_stale();
    let stale_tun_interface = crate::types::get_tun_class_path(&tun_name).exists();
    let stale_bpf = has_pinned_bpf_programs();

    DirtyStateReport {
        stale_rules,
        stale_cgroup,
        stale_tun_interface,
        stale_state_file,
        stale_bpf,
    }
}
