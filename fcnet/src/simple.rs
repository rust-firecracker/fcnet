use fcnet_types::FirecrackerNetwork;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    schema::{NfListObject, NfObject, Rule},
    stmt::{Match, Operator, Statement},
};
use nftables_async::helper::Helper;
use tokio_tun::TunBuilder;

use crate::{
    backend::Backend,
    util::{
        add_base_chains_if_needed, check_base_chains, get_link_index, nat_proto_from_addr, FirecrackerNetworkExt, NO_NFT_ARGS,
    },
    FirecrackerNetworkError, FirecrackerNetworkObjectType, FirecrackerNetworkOperation, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN,
    NFT_TABLE,
};

pub async fn run<B: Backend>(
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
    operation: FirecrackerNetworkOperation,
) -> Result<(), FirecrackerNetworkError> {
    match operation {
        FirecrackerNetworkOperation::Add => add::<B>(network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check::<B>(network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete::<B>(network, netlink_handle).await,
    }
}

async fn add<B: Backend>(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    TunBuilder::new()
        .name(&network.tap_name)
        .tap()
        .persist()
        .up()
        .build()
        .map_err(FirecrackerNetworkError::TapDeviceError)?;
    let tap_idx = crate::util::get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .address()
        .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let current_ruleset = B::NftablesDriver::get_current_ruleset_with_args(network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut masquerade_rule_exists = false;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Rule(rule)
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.table == NFT_TABLE && rule.expr == masq_expr(network) =>
                {
                    masquerade_rule_exists = true;
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    let mut batch = Batch::new();
    add_base_chains_if_needed(&network, &current_ruleset, &mut batch)?;

    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_FILTER_CHAIN.into(),
        expr: forward_expr(network).into(),
        handle: None,
        index: None,
        comment: None,
    }));

    if !masquerade_rule_exists {
        batch.add(NfListObject::Rule(Rule {
            family: network.nf_family(),
            table: NFT_TABLE.into(),
            chain: NFT_POSTROUTING_CHAIN.into(),
            expr: masq_expr(network).into(),
            handle: None,
            index: None,
            comment: None,
        }));
    }

    B::NftablesDriver::apply_ruleset_with_args(&batch.to_nftables(), network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn delete<B: Backend>(
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let current_ruleset = B::NftablesDriver::get_current_ruleset_with_args(network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;

    let mut forward_rule_handle = None;
    let mut masquerade_rule_handle = None;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Rule(rule) if rule.table == NFT_TABLE => {
                    if rule.chain == NFT_FILTER_CHAIN && rule.expr == forward_expr(network) {
                        forward_rule_handle = rule.handle;
                    } else if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == masq_expr(network) {
                        masquerade_rule_handle = rule.handle;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if forward_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfEgressForwardRule,
        ));
    }
    if masquerade_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfMasqueradeRule,
        ));
    }

    let mut batch = Batch::new();
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_FILTER_CHAIN.into(),
        expr: forward_expr(network).into(),
        handle: forward_rule_handle,
        index: None,
        comment: None,
    }));
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.into(),
        chain: NFT_POSTROUTING_CHAIN.into(),
        expr: masq_expr(network).into(),
        handle: masquerade_rule_handle,
        index: None,
        comment: None,
    }));

    B::NftablesDriver::apply_ruleset_with_args(&batch.to_nftables(), network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn check<B: Backend>(
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    get_link_index(network.tap_name.clone(), &netlink_handle).await?;

    let current_ruleset = B::NftablesDriver::get_current_ruleset_with_args(network.nft_program(), NO_NFT_ARGS)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut masquerade_rule_exists = false;
    let mut forward_rule_exists = false;

    check_base_chains(network, &current_ruleset)?;

    for object in current_ruleset.objects.iter() {
        match object {
            NfObject::ListObject(object) => match object {
                NfListObject::Rule(rule) => {
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == masq_expr(network) {
                        masquerade_rule_exists = true;
                    } else if rule.chain == NFT_FILTER_CHAIN && rule.expr == forward_expr(network) {
                        forward_rule_exists = true;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !masquerade_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfMasqueradeRule,
        ));
    }

    if !forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObjectType::NfEgressForwardRule,
        ));
    }

    Ok(())
}

#[inline]
fn masq_expr(network: &FirecrackerNetwork) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                protocol: nat_proto_from_addr(network.guest_ip.address()),
                field: "saddr".into(),
            }))),
            right: Expression::String(network.guest_ip.address().to_string().into()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone().into()),
            op: Operator::EQ,
        }),
        Statement::Masquerade(None),
    ]
}

#[inline]
fn forward_expr(network: &FirecrackerNetwork) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(network.tap_name.clone().into()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone().into()),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]
}
