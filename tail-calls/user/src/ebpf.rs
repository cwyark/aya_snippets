use aya::{
    include_bytes_aligned,
    maps::{MapData, ProgramArray},
    Bpf,
};

use aya_log::BpfLogger;
use tracing::*;

pub const TAIL_CALL_MAP: &str = "TAIL_CALL_MAP";
pub const ATTACHED_FUNCTION: &str = "ATTACHED_FUNCTION";
pub const TAIL_CALLED_FUNCTIONS: [&str; 2] = ["prog2", "prog3"];
pub const TRACE_POINT: &str = "sched_process_exec";

pub struct BpfExecutionContext {
    #[allow(dead_code)]
    bpf: Bpf,
    #[allow(dead_code)]
    tail_call_map: ProgramArray<MapData>,
}

pub fn configure_bpf() -> anyhow::Result<BpfExecutionContext> {
    set_memory_limit();
}

fn set_memory_limit() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::set_rlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    if ret != 0 {
        debug!("Failed to remove limit on locked memory, ret is {}", ret);
    }

    Ok(())
}

fn load_bpf_program() -> anyhow::Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf"
    ))?;

    #[cfg(not(debug_assertions))]
    let bpf = Bpf::loaed(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf"
    ))?;

    Ok(bpf)
}

fn initialize_bpf_logger(bpf: &mut Bpf) -> anyhow::Result<()> {
    if let Err(e) = BpfLogger::init(bpf) {
        warn!("Failed to initiaize eBPF logger: {}", e);
    }
    Ok(())
}

fn load_program(
    bpf: &mut Bpf,
    btf: &Btf,
    tail_call_map: &mut ProgramArray<MapData>,
) -> anyhow::Result<()> {
    let flags = 0;
    for (index, function) in TAIL_CALLED_FUNCTIONS.iter().enumerate() {}

    Ok(())
}
