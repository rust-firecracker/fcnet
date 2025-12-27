use std::{net::IpAddr, str::FromStr};

use cidr::IpInet;
use clap::{Args, Parser, Subcommand, ValueEnum};
use fcnet_types::FirecrackerIpStack;

#[derive(Parser)]
#[command(
    name = "fcnet-cli",
    version = "0.4.5",
    about = "A CLI wrapper around the fcnet library for Firecracker microVM networking",
    propagate_version = true
)]
pub struct Cli {
    #[arg(help = "Optional explicit path to the \"nft\" binary", long = "nft-path")]
    pub nft_path: Option<String>,
    #[arg(help = "Which IP stack to use", long = "ip-stack", default_value_t)]
    pub ip_stack: IpStackWrapper,
    #[arg(help = "The CIDR IP of the guest", long = "guest-ip", default_value_t = IpInet::from_str("172.16.0.2/24").unwrap())]
    pub guest_ip: IpInet,
    #[arg(
        help = "Network interface in the default netns that handles real connectivity",
        long = "iface",
        default_value = "eth0"
    )]
    pub iface_name: String,
    #[arg(help = "Name of the tap device to create", long = "tap", default_value = "tap0")]
    pub tap_name: String,
    #[arg(help = "The CIDR IP of the tap device to create", long = "tap-ip", default_value_t = IpInet::from_str("172.16.0.1/24").unwrap())]
    pub tap_ip: IpInet,
    #[command(flatten)]
    pub operation_group: OperationGroup,
    #[command(subcommand)]
    pub subcommands: Subcommands,
}

#[derive(ValueEnum, Clone, Copy, Default)]
pub enum IpStackWrapper {
    #[default]
    V4,
    V6,
    Dual,
}

impl ToString for IpStackWrapper {
    fn to_string(&self) -> String {
        match self {
            IpStackWrapper::V4 => "v4",
            IpStackWrapper::V6 => "v6",
            IpStackWrapper::Dual => "dual",
        }
        .to_string()
    }
}

impl From<IpStackWrapper> for FirecrackerIpStack {
    fn from(value: IpStackWrapper) -> Self {
        match value {
            IpStackWrapper::V4 => FirecrackerIpStack::V4,
            IpStackWrapper::V6 => FirecrackerIpStack::V6,
            IpStackWrapper::Dual => FirecrackerIpStack::Dual,
        }
    }
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct OperationGroup {
    #[arg(short = 'A', long = "add", help = "Add the given network")]
    pub add: bool,
    #[arg(short = 'D', long = "del", help = "Delete the given network")]
    pub delete: bool,
    #[arg(short = 'C', long = "check", help = "Check the given network")]
    pub check: bool,
}

#[derive(Subcommand, Clone)]
pub enum Subcommands {
    #[command(about = "Use a simple configuration in the default netns")]
    Simple,
    #[command(about = "Use a configuration involving a new netns")]
    Namespaced {
        #[arg(help = "Name of the network namespace", long = "netns", default_value = "fcnet")]
        netns_name: String,
        #[arg(help = "The first end of the veth pair", long = "veth1", default_value = "veth1")]
        veth1_name: String,
        #[arg(help = "The second end of the veth pair", long = "veth2", default_value = "veth0")]
        veth2_name: String,
        #[arg(
            help = "The CIDR IP of the first end of the veth pair",
            long = "veth1-ip",
            default_value_t = IpInet::from_str("10.0.0.1/24").unwrap()
        )]
        veth1_ip: IpInet,
        #[arg(
            help = "The CIDR IP of the second end of the veth pair",
            long = "veth2-ip",
            default_value_t = IpInet::from_str("10.0.0.2/24").unwrap()
        )]
        veth2_ip: IpInet,
        #[arg(
            help = "Optionally, an IP for forwarding connections to the guest from outside the netns (inside, use the actual guest IP)",
            long = "forwarded-guest-ip"
        )]
        forwarded_guest_ip: Option<IpAddr>,
    },
}
