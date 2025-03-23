use std::net::IpAddr;

use cidr::IpInet;
use nftables::{
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    stmt::{Match, NATFamily, Operator, Statement, NAT},
    types::NfFamily,
};

use crate::{
    backend::Backend, util::nat_proto_from_addr, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkOperation,
    FirecrackerNetworkType,
};
use std::future::Future;

mod add;
use add::add;
mod check;
use check::check;
mod delete;
use delete::delete;

struct NamespacedData<'a> {
    netns_name: &'a str,
    veth1_name: &'a str,
    veth2_name: &'a str,
    veth1_ip: &'a IpInet,
    veth2_ip: &'a IpInet,
    forwarded_guest_ip: &'a Option<IpAddr>,
}

pub async fn run<B: Backend>(
    operation: FirecrackerNetworkOperation,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    let namespaced_data = match network.network_type {
        #[cfg(feature = "simple")]
        FirecrackerNetworkType::Simple => unreachable!(),
        FirecrackerNetworkType::Namespaced {
            ref netns_name,
            ref veth1_name,
            ref veth2_name,
            ref veth1_ip,
            ref veth2_ip,
            ref forwarded_guest_ip,
        } => NamespacedData {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            forwarded_guest_ip,
        },
    };

    match operation {
        FirecrackerNetworkOperation::Add => add::<B>(namespaced_data, network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check::<B>(namespaced_data, network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete::<B>(namespaced_data, network).await,
    }
}

#[cfg(feature = "namespaced")]
async fn use_netns_in_thread<B: Backend>(
    netns_name: String,
    future: impl 'static + Send + Future<Output = Result<(), FirecrackerNetworkError>>,
) -> Result<(), FirecrackerNetworkError> {
    use crate::netns::NetNs;

    let netns = NetNs::get(netns_name).map_err(FirecrackerNetworkError::NetnsError)?;
    let (sender, receiver) = futures_channel::oneshot::channel();

    std::thread::spawn(move || {
        let result = B::block_on_current_thread(async move {
            netns.enter().map_err(FirecrackerNetworkError::NetnsError)?;
            future.await
        });

        let _ = sender.send(result);
    });

    match receiver.await {
        Ok(result) => result,
        Err(err) => Err(FirecrackerNetworkError::ChannelCancelError(err)),
    }
}

#[inline]
fn outer_masq_expr(network: &FirecrackerNetwork, namespaced_data: &NamespacedData) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                protocol: nat_proto_from_addr(namespaced_data.veth2_ip.address()),
                field: "saddr".into(),
            }))),
            right: Expression::String(namespaced_data.veth2_ip.address().to_string().into()),
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
fn outer_ingress_forward_expr(network: &FirecrackerNetwork, namespaced_data: &NamespacedData) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(network.iface_name.clone().into()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(namespaced_data.veth1_name.to_string().into()),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]
}

#[inline]
fn outer_egress_forward_expr(network: &FirecrackerNetwork, namespaced_data: &NamespacedData) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone().into()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(namespaced_data.veth1_name.to_string().into()),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]
}

#[inline]
fn inner_snat_expr(veth2_name: String, guest_ip: IpInet, veth2_ip: IpInet, nf_family: NfFamily) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(veth2_name.into()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                protocol: nat_proto_from_addr(guest_ip.address()),
                field: "saddr".into(),
            }))),
            right: Expression::String(guest_ip.address().to_string().into()),
            op: Operator::EQ,
        }),
        Statement::SNAT(Some(NAT {
            addr: Some(Expression::String(veth2_ip.address().to_string().into())),
            family: match nf_family {
                NfFamily::INet => Some(nat_family_from_inet(&veth2_ip)),
                _ => None,
            },
            port: None,
            flags: None,
        })),
    ]
}

#[inline]
fn inner_dnat_expr(
    veth2_name: String,
    forwarded_guest_ip: IpAddr,
    guest_ip: IpInet,
    nf_family: NfFamily,
) -> Vec<Statement<'static>> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(veth2_name.into()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                protocol: nat_proto_from_addr(forwarded_guest_ip),
                field: "daddr".into(),
            }))),
            right: Expression::String(forwarded_guest_ip.to_string().into()),
            op: Operator::EQ,
        }),
        Statement::DNAT(Some(NAT {
            addr: Some(Expression::String(guest_ip.address().to_string().into())),
            family: match nf_family {
                NfFamily::INet => Some(nat_family_from_inet(&guest_ip)),
                _ => None,
            },
            port: None,
            flags: None,
        })),
    ]
}

#[inline]
fn nat_family_from_inet(inet: &IpInet) -> NATFamily {
    match inet {
        IpInet::V4(_) => NATFamily::IP,
        IpInet::V6(_) => NATFamily::IP6,
    }
}
