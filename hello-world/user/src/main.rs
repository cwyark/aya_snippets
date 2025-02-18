mod ebpf;
use tokio::signal;
use tracing::*;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _bpf_context = ebpf::configure_bpf();
    info!("Waiting for Ctrl+C..");
    signal::ctrl_c().await?;
    info!("exit..");
    Ok(())
}
