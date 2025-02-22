use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn handle_tp(ctx: TracePointContext) -> u32 {
    match try_handle_tp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}
fn try_handle_tp(ctx: TracePointContext) -> Result<u32, u64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "pid is {}", pid);
    Ok(0)
}
