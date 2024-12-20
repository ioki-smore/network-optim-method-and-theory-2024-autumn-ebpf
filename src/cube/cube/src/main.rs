use aya::programs::{tc, CgroupAttachMode, SchedClassifier, SockOps, TcAttachType, UProbe};
use aya::Ebpf;
#[rustfmt::skip]
use log::{debug, warn};
use clap::Parser;
use tokio::signal;

mod utils;
use utils::*;

fn attach_mm(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    // let program: &mut KProbe = ebpf.program_mut("cube").unwrap().try_into()?;
    // program.load()?;
    // program.attach("handle_mm_fault", 0)?;
    let malloc_enter: &mut UProbe = ebpf.program_mut("malloc_enter").unwrap().try_into()?;
    malloc_enter.load()?;
    malloc_enter.attach(Some("malloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", None)?;
    let malloc_exit: &mut UProbe = ebpf.program_mut("malloc_exit").unwrap().try_into()?;
    malloc_exit.load()?;
    malloc_exit.attach("malloc".into(), 0, "/lib/x86_64-linux-gnu/libc.so.6", None)?;
    Ok(())
}

fn attach_net(ebpf: &mut Ebpf, ifaces: Vec<&str>) -> anyhow::Result<()> {
    let sock_ops: &mut SockOps = ebpf.program_mut("sock_opts").unwrap().try_into()?;
    sock_ops.load()?;
    sock_ops.attach("/sys/fs/cgroup".into(), CgroupAttachMode::AllowMultiple)?;
    
    for iface in ifaces {
        // error adding clsact to the interface if it is already added is harmless
        // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
        let _ = tc::qdisc_add_clsact(iface);
        let tc_ingress: &mut SchedClassifier =
            ebpf.program_mut("tc_ingress").unwrap().try_into()?;
        tc_ingress.load()?;
        tc_ingress.attach(iface, TcAttachType::Ingress)?;

        let tc_egress: &mut SchedClassifier = ebpf.program_mut("tc_egress").unwrap().try_into()?;
        tc_egress.load()?;
        tc_egress.attach(iface, TcAttachType::Egress)?;
    }
    Ok(())
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // build_pid_pod_map().await.expect("TODO: panic message");

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cube"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // TODO: make it automatic rather hard code
    let ifaces = vec!["veth5902edf0", "veth4c168087"];

    attach_mm(&mut ebpf)?;
    attach_net(&mut ebpf, ifaces)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
