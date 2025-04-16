use std::{
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
};

use cidr::IpInet;
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject, Rule, Table},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use nftables_async::helper::Helper;
use rtnetlink::{LinkMessageBuilder, LinkUnspec, LinkVeth, RouteMessageBuilder};
use tokio_tun::TunBuilder;

use crate::{
    netns::NetNs,
    util::{add_base_chains_if_needed, get_link_index, FirecrackerNetworkExt, NO_NFT_ARGS},
    Backend, FirecrackerNetwork, FirecrackerNetworkError, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_PREROUTING_CHAIN,
    NFT_TABLE,
};

use super::{
    inner_dnat_expr, inner_snat_expr, outer_egress_forward_expr, outer_ingress_forward_expr, outer_masq_expr,
    use_netns_in_thread, NamespacedData,
};

pub(super) async fn add<B: Backend>(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    outer_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    setup_outer_interfaces(&namespaced_data, &outer_handle).await?;

    let tap_name = network.tap_name.clone();
    let tap_ip = network.tap_ip.clone();
    let nft_path = network.nft_path.clone();
    let veth2_name = namespaced_data.veth2_name.to_string();
    let veth1_ip = *namespaced_data.veth1_ip;
    let veth2_ip = *namespaced_data.veth2_ip;
    let guest_ip = network.guest_ip;
    let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
    let nf_family = network.nf_family();
    use_netns_in_thread::<B>(namespaced_data.netns_name.to_string(), async move {
        setup_inner_interfaces::<B>(tap_name, tap_ip, veth2_name.clone(), veth2_ip, veth1_ip).await?;
        setup_inner_nf_rules::<B>(nf_family, nft_path, veth2_name, veth2_ip, forwarded_guest_ip, guest_ip).await
    })
    .await?;

    setup_outer_nf_rules::<B>(&namespaced_data, network).await?;
    setup_outer_forward_route(&namespaced_data, &outer_handle).await
}

async fn setup_outer_interfaces(
    namespaced_data: &NamespacedData<'_>,
    outer_handle: &rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    outer_handle
        .link()
        .add(LinkMessageBuilder::<LinkVeth>::new(namespaced_data.veth1_name, namespaced_data.veth2_name).build())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let veth1_idx = get_link_index(namespaced_data.veth1_name.to_string(), &outer_handle).await?;
    outer_handle
        .address()
        .add(
            veth1_idx,
            namespaced_data.veth1_ip.address(),
            namespaced_data.veth1_ip.network_length(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    outer_handle
        .link()
        .set(
            LinkMessageBuilder::<LinkVeth>::new(namespaced_data.veth1_name, namespaced_data.veth2_name)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let veth2_idx = get_link_index(namespaced_data.veth2_name.to_string(), &outer_handle).await?;
    outer_handle
        .link()
        .set(
            LinkMessageBuilder::<LinkUnspec>::new()
                .index(veth2_idx)
                .setns_by_fd(
                    NetNs::new(&namespaced_data.netns_name)
                        .map_err(FirecrackerNetworkError::NetnsError)?
                        .file()
                        .as_raw_fd(),
                )
                .build(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)
}

async fn setup_outer_nf_rules<B: Backend>(
    namespaced_data: &NamespacedData<'_>,
    network: &FirecrackerNetwork,
) -> Result<(), FirecrackerNetworkError> {
    let current_ruleset = B::NftablesDriver::get_current_ruleset_with_args(network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut batch = Batch::new();
    add_base_chains_if_needed(network, &current_ruleset, &mut batch)?;

    // masquerade veth packets as host iface packets
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_POSTROUTING_CHAIN.into(),
        expr: outer_masq_expr(network, namespaced_data).into(),
        handle: None,
        index: None,
        comment: None,
    }));

    // forward ingress packets from host iface to veth
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_FILTER_CHAIN.into(),
        expr: outer_ingress_forward_expr(network, namespaced_data).into(),
        handle: None,
        index: None,
        comment: None,
    }));

    // forward egress packets from veth to host iface
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_FILTER_CHAIN.into(),
        expr: outer_egress_forward_expr(network, namespaced_data).into(),
        handle: None,
        index: None,
        comment: None,
    }));

    B::NftablesDriver::apply_ruleset_with_args(&batch.to_nftables(), network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn setup_outer_forward_route(
    namespaced_data: &NamespacedData<'_>,
    outer_handle: &rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    // route packets going to forwarded guest ip into the netns, where they are then resolved via DNAT to the
    // guest ip available only in the netns
    if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
        match forwarded_guest_ip {
            IpAddr::V4(v4) => outer_handle.route().add(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(*v4, 32)
                    .gateway(match namespaced_data.veth2_ip.address() {
                        IpAddr::V4(v4) => v4,
                        IpAddr::V6(_) => return Err(FirecrackerNetworkError::ForbiddenDualStackInRoute),
                    })
                    .build(),
            ),
            IpAddr::V6(v6) => outer_handle.route().add(
                RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(*v6, 128)
                    .gateway(match namespaced_data.veth2_ip.address() {
                        IpAddr::V4(_) => return Err(FirecrackerNetworkError::ForbiddenDualStackInRoute),
                        IpAddr::V6(v6) => v6,
                    })
                    .build(),
            ),
        }
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    }
    Ok(())
}

async fn setup_inner_interfaces<B: Backend>(
    tap_name: String,
    tap_ip: IpInet,
    veth2_name: String,
    veth2_ip: IpInet,
    veth1_ip: IpInet,
) -> Result<(), FirecrackerNetworkError> {
    TunBuilder::new()
        .name(&tap_name)
        .tap()
        .persist()
        .up()
        .build()
        .map_err(FirecrackerNetworkError::TapDeviceError)?;
    let (connection, inner_handle, _) =
        rtnetlink::new_connection_with_socket::<B::NetlinkSocket>().map_err(FirecrackerNetworkError::IoError)?;
    B::spawn_connection(connection);

    let veth2_idx = get_link_index(veth2_name.clone(), &inner_handle).await?;
    inner_handle
        .address()
        .add(veth2_idx, veth2_ip.address(), veth2_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    inner_handle
        .link()
        .set(LinkMessageBuilder::<LinkUnspec>::new().index(veth2_idx).up().build())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    match veth1_ip {
        IpInet::V4(ref v4) => inner_handle
            .route()
            .add(RouteMessageBuilder::<Ipv4Addr>::new().gateway(v4.address()).build()),
        IpInet::V6(ref v6) => inner_handle
            .route()
            .add(RouteMessageBuilder::<Ipv6Addr>::new().gateway(v6.address()).build()),
    }
    .execute()
    .await
    .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let tap_idx = get_link_index(tap_name, &inner_handle).await?;
    inner_handle
        .address()
        .add(tap_idx, tap_ip.address(), tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    inner_handle
        .link()
        .set(LinkMessageBuilder::<LinkUnspec>::new().index(tap_idx).up().build())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)
}

async fn setup_inner_nf_rules<B: Backend>(
    nf_family: NfFamily,
    nft_path: Option<String>,
    veth2_name: String,
    veth2_ip: IpInet,
    forwarded_guest_ip: Option<IpAddr>,
    guest_ip: IpInet,
) -> Result<(), FirecrackerNetworkError> {
    let mut batch = Batch::new();

    // create table, postrouting and prerouting chains (prerouting only needed when using forwarding)
    batch.add(NfListObject::Table(Table {
        family: nf_family,
        name: NFT_TABLE.into(),
        handle: None,
    }));

    batch.add(NfListObject::Chain(Chain {
        family: nf_family,
        table: NFT_TABLE.into(),
        name: NFT_POSTROUTING_CHAIN.into(),
        newname: None,
        handle: None,
        _type: Some(NfChainType::NAT),
        hook: Some(NfHook::Postrouting),
        prio: Some(100),
        dev: None,
        policy: Some(NfChainPolicy::Accept),
    }));

    if let Some(_) = forwarded_guest_ip {
        batch.add(NfListObject::Chain(Chain {
            family: nf_family,
            table: NFT_TABLE.into(),
            name: NFT_PREROUTING_CHAIN.into(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Prerouting),
            prio: Some(-100),
            policy: Some(NfChainPolicy::Accept),
            dev: None,
        }));
    }

    // SNAT packets coming from the guest ip to the veth2 ip so that outer netns forwards them not from the
    // guest ip local to the inner netns, but from the known veth2 ip
    batch.add(NfListObject::Rule(Rule {
        family: nf_family,
        table: NFT_TABLE.into(),
        chain: NFT_POSTROUTING_CHAIN.into(),
        expr: inner_snat_expr(veth2_name.clone(), guest_ip, veth2_ip, nf_family).into(),
        handle: None,
        index: None,
        comment: None,
    }));

    // DNAT packets coming to the forwarded guest ip via a route in the outer netns to the actual guest
    // ip local to the inner netns
    if let Some(forwarded_guest_ip) = forwarded_guest_ip {
        batch.add(NfListObject::Rule(Rule {
            family: nf_family,
            table: NFT_TABLE.into(),
            chain: NFT_PREROUTING_CHAIN.into(),
            expr: inner_dnat_expr(veth2_name, forwarded_guest_ip, guest_ip, nf_family).into(),
            handle: None,
            index: None,
            comment: None,
        }));
    }

    B::NftablesDriver::apply_ruleset_with_args(&batch.to_nftables(), nft_path.as_deref(), std::iter::empty::<&OsStr>())
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}
