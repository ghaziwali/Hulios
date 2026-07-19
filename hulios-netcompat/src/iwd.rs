use anyhow::{Context, Result};
use zbus::Connection;

pub async fn monitor_iwd_station_signals(
    fwmark: u32,
    tun_name: String,
    ipv6_enabled: bool,
) -> Result<()> {
    use futures::StreamExt;

    let conn = Connection::system()
        .await
        .context("Failed to connect to D-Bus system bus")?;

    let match_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("net.connman.iwd.Station")?
        .member("StateChanged")?
        .build();

    let mut stream = zbus::MessageStream::for_match_rule(match_rule, &conn, None)
        .await
        .context("Failed to create message stream for iwd Station.StateChanged")?;

    tracing::info!("Subscribed to iwd D-Bus StateChanged signals");

    while let Some(msg_res) = stream.next().await {
        let msg = match msg_res {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("Error reading D-Bus message: {:?}", e);
                continue;
            }
        };

        if let Ok(state) = msg.body().deserialize::<String>() {
            if state == "connected" {
                tracing::info!("iwd connected, re-validating policy routing rules");
                if let Err(e) = hulios_tun::add_policy_rules(fwmark, &tun_name, ipv6_enabled).await
                {
                    tracing::error!("Failed to re-validate policy rules: {:?}", e);
                }
                if let Err(e) = hulios_tun::add_table100_default(&tun_name, ipv6_enabled).await {
                    tracing::debug!("Failed to ensure table 100 route on {}: {:?}", tun_name, e);
                }
            }
        }
    }

    Ok(())
}
