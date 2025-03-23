use std::{borrow::Cow, net::IpAddr};

use fcnet_types::{FirecrackerIpStack, FirecrackerNetwork};
use futures_util::TryStreamExt;
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject, NfObject, Nftables, Table},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

use crate::{FirecrackerNetworkError, FirecrackerNetworkObjectType, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_TABLE};

pub async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> Result<u32, FirecrackerNetworkError> {
    Ok(netlink_handle
        .link()
        .get()
        .match_name(link)
        .execute()
        .try_next()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?
        .ok_or(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObjectType::IpLink))?
        .header
        .index)
}

pub fn add_base_chains_if_needed(
    network: &FirecrackerNetwork,
    current_ruleset: &Nftables,
    batch: &mut Batch,
) -> Result<(), FirecrackerNetworkError> {
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Table(table) if table.name == NFT_TABLE && table.family == network.nf_family() => {
                    table_exists = true;
                }
                NfListObject::Chain(chain) => {
                    if chain.name == NFT_POSTROUTING_CHAIN && chain.table == NFT_TABLE {
                        postrouting_chain_exists = true;
                    } else if chain.name == NFT_FILTER_CHAIN && chain.table == NFT_TABLE {
                        filter_chain_exists = true;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !table_exists {
        batch.add(NfListObject::Table(Table {
            family: network.nf_family(),
            name: NFT_TABLE.into(),
            handle: None,
        }));
    }

    if !postrouting_chain_exists {
        batch.add(NfListObject::Chain(Chain {
            family: network.nf_family(),
            table: NFT_TABLE.into(),
            name: NFT_POSTROUTING_CHAIN.into(),
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Postrouting),
            prio: Some(100),
            policy: Some(NfChainPolicy::Accept),
            newname: None,
            dev: None,
            handle: None,
        }));
    }

    if !filter_chain_exists {
        batch.add(NfListObject::Chain(Chain {
            family: network.nf_family(),
            table: NFT_TABLE.into(),
            name: NFT_FILTER_CHAIN.into(),
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Forward),
            prio: Some(0),
            policy: Some(NfChainPolicy::Accept),
            handle: None,
            newname: None,
            dev: None,
        }));
    }

    Ok(())
}

pub fn check_base_chains(network: &FirecrackerNetwork, current_ruleset: &Nftables) -> Result<(), FirecrackerNetworkError> {
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Table(table) if table.name == NFT_TABLE && table.family == network.nf_family() => {
                    table_exists = true;
                }
                NfListObject::Chain(chain) if chain.table == NFT_TABLE => {
                    if chain.name == NFT_POSTROUTING_CHAIN {
                        postrouting_chain_exists = true;
                    } else if chain.name == NFT_FILTER_CHAIN {
                        filter_chain_exists = true;
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

    if !filter_chain_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfFilterChain,
        ));
    }

    Ok(())
}

#[inline]
pub fn nat_proto_from_addr(addr: IpAddr) -> Cow<'static, str> {
    match addr {
        IpAddr::V4(_) => "ip".into(),
        IpAddr::V6(_) => "ip6".into(),
    }
}

pub trait FirecrackerNetworkExt {
    fn nf_family(&self) -> NfFamily;
    fn nf_program(&self) -> Option<&str>;
}

impl FirecrackerNetworkExt for FirecrackerNetwork {
    #[inline]
    fn nf_family(&self) -> NfFamily {
        match self.ip_stack {
            FirecrackerIpStack::V4 => NfFamily::IP,
            FirecrackerIpStack::V6 => NfFamily::IP6,
            FirecrackerIpStack::Dual => NfFamily::INet,
        }
    }

    #[inline]
    fn nf_program(&self) -> Option<&str> {
        self.nft_path.as_ref().map(|p| p.as_str())
    }
}
