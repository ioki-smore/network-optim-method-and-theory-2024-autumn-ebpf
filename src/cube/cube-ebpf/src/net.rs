use aya_ebpf::bindings::{
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, BPF_TCP_CLOSE,
    TC_ACT_OK,
};
use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_skb_cgroup_id};
use aya_ebpf::macros::sock_ops;
use aya_ebpf::programs::SockOpsContext;

use crate::maps::METRICS;
use aya_ebpf::bindings::sk_action::SK_PASS;
use aya_ebpf::{macros::classifier, programs::TcContext};
use cube_common::Metrics;

unsafe fn try_tc_ingress(ctx: TcContext) -> Result<i32, i32> {
    let tgid = bpf_get_current_pid_tgid();
    
    let cgroup_id = bpf_skb_cgroup_id(ctx.skb.skb);
    let bytes = ctx.len();

    let old = METRICS.get(&cgroup_id).ok_or(0)?;

    METRICS.remove(&cgroup_id).map_err(|e| e as i32)?;

    METRICS
        .insert(
            &cgroup_id,
            &Metrics::increase_rx_bytes(old, bytes as usize),
            0,
        )
        .map_err(|e| e as i32)?;
    Ok(TC_ACT_OK)
}

unsafe fn try_tc_egress(ctx: TcContext) -> Result<i32, i32> {
    let cgroup_id = bpf_skb_cgroup_id(ctx.skb.skb);
    let bytes = ctx.len();

    let old = METRICS.get(&cgroup_id).ok_or(0)?;

    METRICS.remove(&cgroup_id).map_err(|e| e as i32)?;

    METRICS
        .insert(
            &cgroup_id,
            &Metrics::increase_tx_bytes(old, bytes as usize),
            0,
        )
        .map_err(|e| e as i32)?;
    Ok(TC_ACT_OK)
}

#[classifier]
fn tc_ingress(ctx: TcContext) -> i32 {
    unsafe { try_tc_ingress(ctx) }.unwrap_or_else(|ret| ret)
}

#[classifier]
fn tc_egress(ctx: TcContext) -> i32 {
    unsafe { try_tc_egress(ctx) }.unwrap_or_else(|ret| ret)
}

unsafe fn try_sock_ops_monitor(ctx: SockOpsContext) -> Result<u32, u32> {
    let cgroup_id = bpf_get_current_cgroup_id();

    let op = ctx.op();
    match op {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            let old = METRICS.get(&cgroup_id).ok_or(0_u32)?;
            METRICS.remove(&cgroup_id).map_err(|e| e as u32)?;

            METRICS
                .insert(&cgroup_id, &Metrics::increase_conn_count(old), 0)
                .map_err(|e| e as u32)?;
        }
        BPF_TCP_CLOSE => {
            let old = METRICS.get(&cgroup_id).ok_or(0_u32)?;
            METRICS.remove(&cgroup_id).map_err(|e| e as u32)?;
            METRICS
                .insert(&cgroup_id, &Metrics::decrease_conn_count(old), 0)
                .map_err(|e| e as u32)?;
        }
        _ => {}
    }
    Ok(SK_PASS)
}

#[sock_ops]
fn sock_ops_monitor(ctx: SockOpsContext) -> u32 {
    unsafe { try_sock_ops_monitor(ctx) }.unwrap_or_else(|ret| ret)
}
