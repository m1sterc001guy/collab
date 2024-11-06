use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let gw_lnd = dev_fed.gw_lnd().await?;
        let info = gw_lnd.get_info().await?;
        info!(?info, "GW LND Info");
        Ok(())
    })
    .await
}
