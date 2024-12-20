use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use std::error::Error;

use kube::api::ListParams;
use std::process::Command;

pub async fn build_pid_pod_map() -> Result<(), Box<dyn Error>> {
    let namespace = "default";
    let label_selector = "app in (service2,service3)";
    
    let client = Client::try_default().await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    
    // let lp = ListParams::default().labels(label_selector);
    let lp = ListParams::default();
    let pod_list = pods.list(&lp).await?;
    
    for pod in pod_list.items {
        if let Some(pod_name) = pod.metadata.name.clone() {
            println!("Processing Pod: {}", pod_name);

            if let Some(status) = pod.status {
                if let Some(container_statuses) = status.container_statuses {
                    for container_status in container_statuses {
                        let container_name = container_status.name;
                        let container_id = container_status
                            .container_id
                            .unwrap_or_else(|| "Unknown".to_string());

                        println!("  Container: {}", container_name);
                        println!("  Container ID: {}", container_id);
                        
                        if let Some(pid) = get_pid_from_container_runtime(&container_id) {
                            println!("  PID: {}", pid);
                        } else {
                            println!("  Failed to retrieve PID for container: {}", container_name);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn get_pid_from_container_runtime(container_id: &str) -> Option<String> {
    if container_id.starts_with("containerd://") {
        let runtime_id = container_id.strip_prefix("containerd://").unwrap();
        return run_crictl_command(runtime_id);
    } else if container_id.starts_with("docker://") {
        let runtime_id = container_id.strip_prefix("docker://").unwrap();
        return run_docker_command(runtime_id);
    }
    None
}

// 使用 crictl 获取 PID
fn run_crictl_command(runtime_id: &str) -> Option<String> {
    let output = Command::new("crictl")
        .arg("inspect")
        .arg("--output")
        .arg("go-template")
        .arg("--template")
        .arg("{{.info.pid}}")
        .arg(runtime_id)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Some(pid);
        }
    }
    None
}

fn run_docker_command(runtime_id: &str) -> Option<String> {
    let output = Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{.State.Pid}}")
        .arg(runtime_id)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Some(pid);
        }
    }
    None
}

    // async fn update_metrics(&mut self) -> Result<()> {
    //     let mut remove_keys = Vec::new();
    //
    //     // 遍历 eBPF Map
    //     let mut entries = self.pod_stats_map.iter()?;
    //     while let Some((cgroup_id, stats)) = entries.next() {
    //         let cgroup_id = u64::from_ne_bytes(cgroup_id.try_into()?);
    //         let stats: PodStats = stats.try_into()?;
    //
    //         if let Some(pod_info) = self.cgroup_pod_map.get(&cgroup_id) {
    //             let labels = [pod_info.name.as_str(), pod_info.namespace.as_str()];
    //
    //             self.mem_usage_gauge
    //                 .with_label_values(&labels)
    //                 .set(stats.mem_usage as i64);
    //
    //             self.conn_count_gauge
    //                 .with_label_values(&labels)
    //                 .set(stats.conn_count as i64);
    //
    //             self.rx_bytes_counter
    //                 .with_label_values(&labels)
    //                 .inc_by(stats.rx_bytes);
    //
    //             self.tx_bytes_counter
    //                 .with_label_values(&labels)
    //                 .inc_by(stats.tx_bytes);
    //
    //             // 清除已读取的数据，防止重复计算
    //             let zero_stats = PodStats::default();
    //             self.pod_stats_map.insert(cgroup_id, zero_stats, 0)?;
    //         } else {
    //             // 如果找不到对应的 Pod 信息，可能是 Pod 已经删除，记录下来待会删除
    //             remove_keys.push(cgroup_id);
    //         }
    //     }
    //
    //     // 从 eBPF Map 中删除无效的 cgroup ID
    //     for cgroup_id in remove_keys {
    //         self.pod_stats_map.remove(cgroup_id)?;
    //     }
    //
    //     Ok(())

