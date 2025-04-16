#[cfg(feature = "smol-backend")]
use async_executor::{Executor, LocalExecutor};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_proto::Connection;
use std::future::Future;
#[cfg(feature = "smol-backend")]
use std::sync::{Arc, OnceLock};

/// The [Backend] trait encapsulates the async-runtime-dependent functionality that is needed for fcnet
/// to function.
pub trait Backend: Send + Sync + 'static {
    /// The [netlink_sys] socket (async fd implementation) used by this backend.
    type NetlinkSocket: netlink_sys::AsyncSocket + Send;
    /// The [nftables_async] driver used by this backend.
    type NftablesDriver: nftables_async::driver::Driver;

    /// Spawn a netlink [Connection] onto this async runtime, detaching the spawned task to have it run
    /// in the background.
    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>);

    /// Create a thread-local, !Send async executor from this runtime and block it on the given future.
    /// This will be called in a separate OS thread spawned by fcnet for the purposes of calling setns
    /// within it to operate within the context of another network namespace.
    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O;
}

/// A [Backend] implementation that uses the tokio crate for async I/O and its current-thread executor.
#[cfg(feature = "tokio-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-backend")))]
pub struct TokioBackend;

#[cfg(feature = "tokio-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-backend")))]
impl Backend for TokioBackend {
    type NetlinkSocket = netlink_proto::sys::TokioSocket;
    type NftablesDriver = nftables_async::driver::TokioDriver;

    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>) {
        tokio::task::spawn(connection);
    }

    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Could not build current-thread Tokio runtime. This panic should be isolated to another thread")
            .block_on(future)
    }
}

#[cfg(feature = "smol-backend")]
static SMOL_EXECUTOR: OnceLock<Arc<Executor>> = OnceLock::new();

/// A [Backend] implementation that uses the async-process and async-executor crates from the Smol stack.
/// [SmolBackend] must be initialized by passing it an [Arc] of an [Executor<'static>], otherwise functions that
/// spawn tasks on an executor will panic.
#[cfg(feature = "smol-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol-backend")))]
pub struct SmolBackend;

#[cfg(feature = "smol-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol-backend")))]
impl SmolBackend {
    /// Initializes the backend with the given [Arc] of an [Executor<'static>] from the async-executor crate.
    /// This can only be done once per application, as it uses [OnceLock] internally, and should only be performed
    /// within binary code.
    pub fn initialize(executor: impl Into<Arc<Executor<'static>>>) {
        SMOL_EXECUTOR
            .set(executor.into())
            .expect("Smol executor was already initialized");
    }
}

#[cfg(feature = "smol-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol-backend")))]
impl Backend for SmolBackend {
    type NetlinkSocket = netlink_proto::sys::SmolSocket;
    type NftablesDriver = nftables_async::driver::AsyncProcessDriver;

    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>) {
        SMOL_EXECUTOR
            .get()
            .expect("Smol executor wasn't initialized")
            .spawn(connection)
            .detach();
    }

    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O {
        async_io::block_on(LocalExecutor::new().run(future))
    }
}
