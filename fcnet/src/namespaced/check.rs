use std::net::IpAddr;

use cidr::IpInet;
use futures_util::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use nftables::{
    schema::{NfListObject, NfObject},
    types::NfFamily,
};
use nftables_async::get_current_ruleset;
use rtnetlink::RouteMessageBuilder;

use crate::{
    backend::Backend,
    util::{check_base_chains, FirecrackerNetworkExt},
    FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkObjectType, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN,
    NFT_PREROUTING_CHAIN, NFT_TABLE,
};

use super::{
    inner_dnat_expr, inner_snat_expr, outer_egress_forward_expr, outer_ingress_forward_expr, outer_masq_expr,
    use_netns_in_thread, NamespacedData,
};

pub(super) async fn check<B: Backend>(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    check_outer_nf_rules::<B>(network, &namespaced_data).await?;

    let nft_path = network.nft_path.clone();
    let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
    let veth2_name = namespaced_data.veth2_name.to_string();
    let veth2_ip = *namespaced_data.veth2_ip;
    let guest_ip = network.guest_ip;
    let nf_family = network.nf_family();

    use_netns_in_thread::<B>(namespaced_data.netns_name.to_string(), async move {
        check_inner_nf_rules::<B>(nft_path, forwarded_guest_ip, veth2_name, guest_ip, veth2_ip, nf_family).await
    })
    .await?;

    check_outer_forward_route(namespaced_data, netlink_handle).await
}

async fn check_outer_nf_rules<B: Backend>(
    network: &FirecrackerNetwork,
    namespaced_data: &NamespacedData<'_>,
) -> Result<(), FirecrackerNetworkError> {
    let current_ruleset = get_current_ruleset::<B::NftablesProcess>(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    check_base_chains(network, &current_ruleset)?;

    let mut outer_masq_rule_exists = false;
    let mut outer_ingress_forward_rule_exists = false;
    let mut outer_egress_forward_rule_exists = false;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Rule(rule) if rule.table == NFT_TABLE.to_string() => {
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == outer_masq_expr(network, &namespaced_data) {
                        outer_masq_rule_exists = true;
                    } else if rule.chain == NFT_FILTER_CHAIN {
                        if rule.expr == outer_ingress_forward_expr(network, &namespaced_data) {
                            outer_ingress_forward_rule_exists = true;
                        } else if rule.expr == outer_egress_forward_expr(network, &namespaced_data) {
                            outer_egress_forward_rule_exists = true;
                        }
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !outer_masq_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfMasqueradeRule,
        ));
    }

    if !outer_ingress_forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfIngressForwardRule,
        ));
    }

    if !outer_egress_forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfEgressForwardRule,
        ));
    }

    Ok(())
}

async fn check_outer_forward_route(
    namespaced_data: NamespacedData<'_>,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
        let mut route_message = None;
        let mut route_message_stream = netlink_handle
            .route()
            .get(RouteMessageBuilder::<IpAddr>::new().build())
            .execute();

        while let Ok(Some(current_route_message)) = route_message_stream.try_next().await {
            for attribute in &current_route_message.attributes {
                if let RouteAttribute::Destination(route_addr) = attribute {
                    let ip_addr = match route_addr {
                        RouteAddress::Inet(i) => IpAddr::V4(*i),
                        RouteAddress::Inet6(i) => IpAddr::V6(*i),
                        _ => continue,
                    };

                    if ip_addr == *forwarded_guest_ip {
                        route_message = Some(current_route_message);
                        break;
                    }
                }
            }
        }

        if route_message.is_none() {
            return Err(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObjectType::IpRoute));
        }
    }

    Ok(())
}

async fn check_inner_nf_rules<B: Backend>(
    nft_path: Option<String>,
    forwarded_guest_ip: Option<IpAddr>,
    veth2_name: String,
    guest_ip: IpInet,
    veth2_ip: IpInet,
    nf_family: NfFamily,
) -> Result<(), FirecrackerNetworkError> {
    let current_ruleset = get_current_ruleset::<B::NftablesProcess>(nft_path.as_deref(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;

    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut prerouting_chain_exists = false;
    let mut snat_rule_exists = false;
    let mut dnat_rule_exists = false;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Table(table) if table.name == NFT_TABLE => {
                    table_exists = true;
                }
                NfListObject::Chain(chain) if chain.table == NFT_TABLE => {
                    if chain.name == NFT_POSTROUTING_CHAIN {
                        postrouting_chain_exists = true;
                    } else if chain.name == NFT_PREROUTING_CHAIN {
                        prerouting_chain_exists = true;
                    }
                }
                NfListObject::Rule(rule) => {
                    if rule.chain == NFT_POSTROUTING_CHAIN
                        && rule.expr == inner_snat_expr(veth2_name.clone(), guest_ip, veth2_ip, nf_family)
                    {
                        snat_rule_exists = true;
                    } else if let Some(forwarded_guest_ip) = forwarded_guest_ip {
                        if rule.chain == NFT_PREROUTING_CHAIN
                            && rule.expr == inner_dnat_expr(veth2_name.clone(), forwarded_guest_ip, guest_ip, nf_family)
                        {
                            dnat_rule_exists = true;
                        }
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !table_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObjectType::NfTable));
    }

    if !postrouting_chain_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfPostroutingChain,
        ));
    }

    if !snat_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfEgressSnatRule,
        ));
    }

    if forwarded_guest_ip.is_some() {
        if !prerouting_chain_exists {
            return Err(FirecrackerNetworkError::ObjectNotFound(
                FirecrackerNetworkObjectType::NfPreroutingChain,
            ));
        }

        if !dnat_rule_exists {
            return Err(FirecrackerNetworkError::ObjectNotFound(
                FirecrackerNetworkObjectType::NfIngressDnatRule,
            ));
        }
    }

    Ok(())
}
