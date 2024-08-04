use std::str::FromStr;

use cidr::{IpInet, Ipv4Inet};
use clap::{Args, Parser, Subcommand};
use futures::TryStreamExt;
use tokio::process::Command;

mod netns;
mod simple;

#[derive(Parser)]
#[command(
    name = "nat-helper",
    version = "0.1",
    about = "NAT helper for Firecracker workloads",
    propagate_version = true
)]
pub struct Cli {
    #[arg(
        help = "Path to the iptables binary to use for veth and NAT-related routing, iptables-nft is supported",
        long = "iptables-path",
        default_value = "/usr/sbin/iptables"
    )]
    iptables_path: String,
    #[arg(
        help = "Network interface in the default netns that handles real connectivity",
        long = "iface",
        default_value = "eth0"
    )]
    iface_name: String,
    #[arg(
        help = "Name of the tap device to create",
        long = "tap",
        default_value = "tap0"
    )]
    tap_name: String,
    #[arg(help = "The CIDR IP of the tap device to create", long = "tap-ip", default_value_t = Ipv4Inet::from_str("10.0.0.1/24").unwrap())]
    tap_ip: Ipv4Inet,
    #[command(flatten)]
    add_or_del_group: AddOrDelGroup,
    #[command(subcommand)]
    subcommands: Subcommands,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct AddOrDelGroup {
    #[arg(short = 'A', long = "add", help = "Add the given network")]
    add: bool,
    #[arg(short = 'D', long = "del", help = "Delete the given network")]
    del: bool,
    #[arg(short = 'C', long = "check", help = "Check the given network")]
    check: bool,
}

#[derive(Subcommand)]
pub enum Subcommands {
    #[command(about = "Use a simple configuration in the default netns")]
    Simple,
    #[command(about = "Use a configuration involving a new netns")]
    Netns {
        #[arg(
            help = "Name of the network namespace to be created and connected",
            long = "netns",
            default_value = "fcnet"
        )]
        netns_name: String,
        #[arg(
            help = "The first end of the veth pair, applicable for a netns config",
            long = "veth1",
            default_value = "veth0"
        )]
        veth1_name: String,
        #[arg(
            help = "The second end of the veth pair, applicable for a netns config",
            long = "veth2",
            default_value = "vpeer0"
        )]
        veth2_name: String,
        #[arg(
            help = "The CIDR IP of the first end of the veth pair, applicable for a netns config",
            long = "veth1-ip",
            default_value_t = IpInet::from_str("10.0.0.2/24").unwrap()
        )]
        veth1_ip: IpInet,
        #[arg(
            help = "The CIDR IP of the second end of the veth pair, applicable for a netns config",
            long = "veth2-ip",
            default_value_t = IpInet::from_str("10.0.0.3/24").unwrap()
        )]
        veth2_ip: IpInet,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (connection, netlink_handle, _) =
        rtnetlink::new_connection().expect("Could not connect to rtnetlink");
    tokio::spawn(connection);

    match cli.subcommands {
        Subcommands::Simple => {
            simple::run(&cli, &netlink_handle).await;
        }
        #[allow(unused)]
        Subcommands::Netns {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
        } => todo!(),
    };
}

// utils

pub async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> u32 {
    netlink_handle
        .link()
        .get()
        .match_name(link)
        .execute()
        .try_next()
        .await
        .expect("Could not query for a link's index")
        .unwrap()
        .header
        .index
}

pub async fn run_iptables(cli: &Cli, iptables_cmd: String) {
    let mut command = Command::new(cli.iptables_path.as_str());
    for iptables_arg in iptables_cmd.split(' ') {
        command.arg(iptables_arg);
    }

    let status = command.status().await.expect("Could not invoke iptables");
    if !status.success() {
        panic!("Iptables invocation failed with exit status: {}", status);
    }
}
