use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::btf_tracepoint, programs::BtfTracePointContext,
};

#[btf_tracepoint(function = "handle_tp")]
pub fn handle_tp(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_handle_tp(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_handle_tp(ctx: BtfTracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    Ok(0)
}
