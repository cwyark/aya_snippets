use aya::{
    include_bytes_aligned,
    maps::{MapData, ProgramArray},
    programs::BtfTracePoint,
    Btf, Ebpf,
};
use aya_log::EbpfLogger;

pub const ATTACHED_FUNCTION: &str = "prog1";
pub const TRACE_POINT: &str = "sched_process_exec";

pub struct BpfExecutionContext {
    #[allow(dead_code)]
    bpf: Ebpf,
}

pub fn configure_bpf() -> anyhow::Result<BpfExecutionContext> {
    let mut bpf = load_bpf_program()?;
    initialize_bpf_logger(&mut bpf)?;

    let btf = Btf::from_sys_fs()?;
    let mut tail_call_map = ProgramArray::try_from(bpf.take_map(TAIL_CALL_MAP).unwrap())?;

    load_programs(&mut bpf, &btf, &mut tail_call_map)?;

    Ok(BpfExecutionContext { bpf, tail_call_map })
}

fn load_bpf_program() -> anyhow::Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf"
    ))?;
    Ok(bpf)
}

fn initialize_bpf_logger(bpf: &mut Bpf) -> anyhow::Result<()> {
    if let Err(e) = EbpfLogger::init(bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    Ok(())
}

fn load_programs(
    bpf: &mut Bpf,
    btf: &Btf,
    tail_call_map: &mut ProgramArray<MapData>,
) -> anyhow::Result<()> {
    let flags = 0;

    let attached_program: &mut BtfTracePoint =
        bpf.program_mut(ATTACHED_FUNCTION).unwrap().try_into()?;
    attached_program.load(TRACE_POINT, btf)?;
    attached_program.attach()?;

    Ok(())
}
