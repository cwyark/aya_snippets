use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::raw_tracepoint, programs::RawTracePointContext,
};
use aya_log_ebpf::info;

#[raw_tracepoint]
pub fn handle_tp(ctx: RawTracePointContext) -> u32 {
    match try_handle_tp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

fn try_handle_tp(ctx: RawTracePointContext) -> Result<u32, u64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "pid is {}", pid);
    Ok(0)
}
