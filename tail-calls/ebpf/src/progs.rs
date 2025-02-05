use crate::maps;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_smp_processor_id},
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};

use aya_log_ebpf::*;

#[btf_tracepoint(function = "prog1")]
pub fn prog1(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_prog1(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_prog1(ctx: BtfTracePointContext) -> Result<u32, i64> {
    let cpu_id = bpf_get_smp_processor_id();
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let shared_state = unsafe {
        let ptr = maps::PER_CPU_MAP.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };

    shared_state.per_event_count = 1;

    info!(
        &ctx,
        "[prog1] cpu_id: {}, tgid: {}, per_event_count: {}, total_count: {}",
        cpu_id,
        tgid,
        shared_state.per_event_count,
        shared_state.total_count
    );

    let res = maps::TAIL_CALL_MAP.tail_call(&ctx, 0);
    if res.is_err() {
        error!(&ctx, "prog1: tail_call failed");
    }

    Ok(0)
}
