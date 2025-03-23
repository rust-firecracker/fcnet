use nftables::{
    batch::Batch,
    schema::{NfListObject, NfObject, Rule},
};
use nftables_async::{apply_ruleset, get_current_ruleset};

use crate::{
    backend::Backend, netns::NetNs, util::FirecrackerNetworkExt, FirecrackerNetwork, FirecrackerNetworkError,
    FirecrackerNetworkObjectType, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_TABLE,
};

use super::{outer_egress_forward_expr, outer_ingress_forward_expr, outer_masq_expr, NamespacedData};

pub(super) async fn delete<B: Backend>(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
) -> Result<(), FirecrackerNetworkError> {
    NetNs::get(&namespaced_data.netns_name)
        .map_err(FirecrackerNetworkError::NetnsError)?
        .remove()
        .map_err(FirecrackerNetworkError::NetnsError)?;

    let current_ruleset = get_current_ruleset::<B::NftablesProcess>(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;

    let mut outer_masq_rule_handle = None;
    let mut outer_ingress_forward_rule_handle = None;
    let mut outer_egress_forward_rule_handle = None;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Rule(rule) if rule.table == NFT_TABLE.to_string() => {
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == outer_masq_expr(network, &namespaced_data) {
                        outer_masq_rule_handle = rule.handle;
                    } else if rule.chain == NFT_FILTER_CHAIN {
                        if rule.expr == outer_ingress_forward_expr(network, &namespaced_data) {
                            outer_ingress_forward_rule_handle = rule.handle;
                        } else if rule.expr == outer_egress_forward_expr(network, &namespaced_data) {
                            outer_egress_forward_rule_handle = rule.handle;
                        }
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if outer_masq_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfMasqueradeRule,
        ));
    }

    if outer_ingress_forward_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfIngressForwardRule,
        ));
    }

    if outer_egress_forward_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfEgressForwardRule,
        ));
    }

    let mut batch = Batch::new();
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_POSTROUTING_CHAIN.into(),
        expr: outer_masq_expr(network, &namespaced_data).into(),
        handle: outer_masq_rule_handle,
        index: None,
        comment: None,
    }));
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_FILTER_CHAIN.into(),
        expr: outer_ingress_forward_expr(network, &namespaced_data).into(),
        handle: outer_ingress_forward_rule_handle,
        index: None,
        comment: None,
    }));
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_FILTER_CHAIN.into(),
        expr: outer_egress_forward_expr(network, &namespaced_data).into(),
        handle: outer_egress_forward_rule_handle,
        index: None,
        comment: None,
    }));

    apply_ruleset::<B::NftablesProcess>(batch.to_nftables(), network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}
