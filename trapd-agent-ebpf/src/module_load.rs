use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

/// Kernel module load event — every insmod/modprobe is a rootkit risk.
#[repr(C)]
pub struct ModuleLoadEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub gid:      u32,
    pub taints:   u32,
    pub name:     [u8; 64],
    pub name_len: u32,
}

/// 256 KiB – module loads are rare; all are tracked.
#[map]
static MODULE_LOAD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: module/module_load
///
/// Record layout:
///   offset  8 │ u32  taints
///   offset 12 │ u32  __data_loc name  (bits[15:0]=offset, bits[31:16]=len)
#[tracepoint]
pub fn module_load(ctx: TracePointContext) -> u32 {
    match try_module_load(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_module_load(ctx: &TracePointContext) -> Result<(), i64> {
    let taints:   u32 = unsafe { ctx.read_at(8).map_err(|_| -1i64)? };
    let data_loc: u32 = unsafe { ctx.read_at(12).map_err(|_| -1i64)? };

    // bits[15:0] = byte offset from TP record start to the NUL-terminated name
    let name_offset = (data_loc & 0xFFFF) as usize;
    let name_ptr = (ctx.as_ptr() as usize).checked_add(name_offset).ok_or(-1i64)? as *const u8;

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut entry = MODULE_LOAD_EVENTS.reserve::<ModuleLoadEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid    = pid;
    ev.uid    = uid;
    ev.gid    = gid;
    ev.taints = taints;

    let written = unsafe {
        bpf_probe_read_kernel_str_bytes(name_ptr, &mut ev.name)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    ev.name_len = written as u32;

    entry.submit(0);
    Ok(())
}
