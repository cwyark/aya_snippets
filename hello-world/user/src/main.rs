mod ebpf;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    ebpf::configure_ebpf()?;
    println!("Waiting for Ctrl+C..");
    signal::ctrl_c().await?;
    println!("exit..");
    Ok(())
}
