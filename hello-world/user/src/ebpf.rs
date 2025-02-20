use aya::{include_bytes_aligned, programs::RawTracePoint, Ebpf};
use aya_log::EbpfLogger;

pub const ATTACHED_FUNCTION: &str = "handle_tp";
pub const TRACE_POINT: &str = "sys_enter_write";

pub struct EbpfExecutionContext {
    #[allow(dead_code)]
    ebpf: Ebpf,
}

pub fn configure_bpf() -> anyhow::Result<EbpfExecutionContext> {
    let mut ebpf = load_ebpf_program()?;

    initialize_ebpf_logger(&mut ebpf)?;

    load_programs(&mut ebpf)?;

    Ok(EbpfExecutionContext { ebpf: ebpf })
}

fn load_ebpf_program() -> anyhow::Result<Ebpf> {
    #[cfg(debug_assertions)]
    let ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf"
    ))?;
    Ok(ebpf)
}

fn initialize_ebpf_logger(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    if let Err(e) = EbpfLogger::init(ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        println!("Failed to initialize eBPF logger: {}", e);
    }
    Ok(())
}

fn load_programs(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut RawTracePoint = ebpf.program_mut(ATTACHED_FUNCTION).unwrap().try_into()?;
    program.load()?;
    program.attach(TRACE_POINT)?;
    Ok(())
}
