//! Trouble is a Bluetooth Low Energy (BLE) Host implementation that communicates
//! with a controller over any transport implementing the traits from the `bt-hci`
//! crate.
//!
//! Trouble can run on embedded devices (`no_std`) and be configured to consume
//! as little resources are needed depending on your required configuration.
#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
#![warn(missing_docs)]

use core::mem::MaybeUninit;

use advertise::AdvertisementDataError;
pub use bt_hci::param::{AddrKind, BdAddr, LeConnRole as Role};
use bt_hci::FromHciBytesError;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use crate::channel_manager::{ChannelStorage, PacketChannel};
use crate::connection_manager::ConnectionStorage;
use crate::l2cap::sar::SarType;
use crate::packet_pool::{PacketPool, Qos};

use crate::att::AttErrorCode;

mod fmt;

#[cfg(not(any(feature = "central", feature = "peripheral")))]
compile_error!("Must enable at least one of the `central` or `peripheral` features");

mod att;
pub mod central;
mod channel_manager;
mod codec;
mod command;
pub mod config;
mod connection_manager;
mod cursor;
pub mod packet_pool;
mod pdu;
pub mod peripheral;
pub mod types;

pub use packet_pool::Qos as PacketQos;

pub mod advertise;
pub mod connection;
pub mod l2cap;
pub mod scan;

#[cfg(test)]
pub(crate) mod mock_controller;

pub(crate) mod host;
pub use central::*;
use host::{AdvHandleState, BleHost, Runner};
pub use peripheral::*;

#[allow(missing_docs)]
pub mod prelude {
    #[cfg(feature = "peripheral")]
    pub use crate::advertise::*;
    #[cfg(feature = "central")]
    pub use crate::central::*;
    #[cfg(feature = "peripheral")]
    pub use crate::peripheral::*;

    pub use super::Controller;
    pub use crate::connection::*;
    pub use crate::l2cap::*;
    pub use crate::Address;

    #[cfg(feature = "gatt")]
    pub use crate::attribute::*;
    #[cfg(feature = "gatt")]
    pub use crate::gatt::*;

    #[cfg(feature = "peripheral")]
    pub use crate::scan::*;

    pub use crate::host::Runner;

    pub use super::BleHostError;
    pub use super::Error;
    pub use super::HostResources;
    pub use super::Stack;
    pub use crate::packet_pool::PacketPool;
    pub use crate::packet_pool::Qos as PacketQos;
}

#[cfg(feature = "gatt")]
pub mod attribute;
#[cfg(feature = "gatt")]
mod attribute_server;
#[cfg(feature = "gatt")]
pub mod gatt;

/// A BLE address.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Address {
    /// Address type.
    pub kind: AddrKind,
    /// Address value.
    pub addr: BdAddr,
}

impl Address {
    /// Create a new random address.
    pub fn random(val: [u8; 6]) -> Self {
        Self {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new(val),
        }
    }
}

/// Errors returned by the host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BleHostError<E> {
    /// Error from the controller.
    Controller(E),
    /// Error from the host.
    BleHost(Error),
}

/// Errors related to Host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Error encoding parameters for HCI commands.
    Hci(bt_hci::param::Error),
    /// Error decoding responses from HCI commands.
    HciDecode(FromHciBytesError),
    /// Error from the Attribute Protocol.
    Att(AttErrorCode),
    /// Insufficient space in the buffer.
    InsufficientSpace,
    /// Invalid value.
    InvalidValue,
    /// Error decoding advertisement data.
    Advertisement(AdvertisementDataError),
    /// Invalid l2cap channel id provided.
    InvalidChannelId,
    /// No l2cap channel available.
    NoChannelAvailable,
    /// Resource not found.
    NotFound,
    /// Invalid state.
    InvalidState,
    /// Out of memory.
    OutOfMemory,
    /// Unsupported operation.
    NotSupported,
    /// L2cap channel closed.
    ChannelClosed,
    /// Operation timed out.
    Timeout,
    /// Controller is busy.
    Busy,
    /// No send permits available.
    NoPermits,
    /// Connection is disconnected.
    Disconnected,
    /// Other error.
    Other,
}

impl<E> From<Error> for BleHostError<E> {
    fn from(value: Error) -> Self {
        Self::BleHost(value)
    }
}

impl From<FromHciBytesError> for Error {
    fn from(error: FromHciBytesError) -> Self {
        Self::HciDecode(error)
    }
}

impl From<AttErrorCode> for Error {
    fn from(error: AttErrorCode) -> Self {
        Self::Att(error)
    }
}

impl<E> From<bt_hci::cmd::Error<E>> for BleHostError<E> {
    fn from(error: bt_hci::cmd::Error<E>) -> Self {
        match error {
            bt_hci::cmd::Error::Hci(p) => Self::BleHost(Error::Hci(p)),
            bt_hci::cmd::Error::Io(p) => Self::Controller(p),
        }
    }
}

impl<E> From<bt_hci::param::Error> for BleHostError<E> {
    fn from(error: bt_hci::param::Error) -> Self {
        Self::BleHost(Error::Hci(error))
    }
}

impl From<codec::Error> for Error {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => Error::InsufficientSpace,
            codec::Error::InvalidValue => Error::InvalidValue,
        }
    }
}

impl<E> From<codec::Error> for BleHostError<E> {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => BleHostError::BleHost(Error::InsufficientSpace),
            codec::Error::InvalidValue => BleHostError::BleHost(Error::InvalidValue),
        }
    }
}

use bt_hci::cmd::controller_baseband::*;
use bt_hci::cmd::le::*;
use bt_hci::cmd::link_control::*;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

/// Trait that defines the controller implementation required by the host.
///
/// The controller must implement the required commands and events to be able to be used with Trouble.
pub trait Controller:
    bt_hci::controller::Controller
    + embedded_io::ErrorType
    + ControllerCmdSync<LeReadBufferSize>
    + ControllerCmdSync<Disconnect>
    + ControllerCmdSync<SetEventMask>
    + ControllerCmdSync<LeSetEventMask>
    + ControllerCmdSync<LeSetRandomAddr>
    + ControllerCmdSync<HostBufferSize>
    + ControllerCmdAsync<LeConnUpdate>
    + ControllerCmdSync<LeReadFilterAcceptListSize>
    + ControllerCmdSync<SetControllerToHostFlowControl>
    + ControllerCmdSync<Reset>
    + ControllerCmdSync<LeCreateConnCancel>
    + ControllerCmdAsync<LeCreateConn>
    + ControllerCmdSync<LeClearFilterAcceptList>
    + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
    + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
    + ControllerCmdSync<LeReadBufferSize>
    + for<'t> ControllerCmdSync<LeSetAdvData>
    + ControllerCmdSync<LeSetAdvParams>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetScanResponseData>
{
}

impl<
        C: bt_hci::controller::Controller
            + embedded_io::ErrorType
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdAsync<LeCreateConn>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>
            + for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>,
    > Controller for C
{
}

/// HostResources holds the resources used by the host.
///
/// The l2cap packet pool is used by the host to handle inbound data, by allocating space for
/// incoming packets and dispatching to the appropriate connection and channel.
pub struct HostResources<
    C: Controller,
    const CONNS: usize,
    const CHANNELS: usize,
    const L2CAP_MTU: usize,
    const ADV_SETS: usize = 1,
> {
    qos: Qos,
    rx_pool: MaybeUninit<PacketPool<NoopRawMutex, L2CAP_MTU, { config::L2CAP_RX_PACKET_POOL_SIZE }, CHANNELS>>,
    connections: MaybeUninit<[ConnectionStorage; CONNS]>,
    channels: MaybeUninit<[ChannelStorage; CHANNELS]>,
    channels_rx: MaybeUninit<[PacketChannel<'static, { config::L2CAP_RX_QUEUE_SIZE }>; CHANNELS]>,
    sar: MaybeUninit<[SarType<'static>; CONNS]>,
    advertise_handles: MaybeUninit<[AdvHandleState; ADV_SETS]>,
    inner: MaybeUninit<BleHost<'static, C>>,
}

impl<C: Controller, const CONNS: usize, const CHANNELS: usize, const L2CAP_MTU: usize, const ADV_SETS: usize>
    HostResources<C, CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>
{
    /// Create a new instance of host resources with the provided QoS requirements for packets.
    pub fn new(qos: Qos) -> Self {
        Self {
            qos,
            rx_pool: MaybeUninit::uninit(),
            connections: MaybeUninit::uninit(),
            sar: MaybeUninit::uninit(),
            channels: MaybeUninit::uninit(),
            channels_rx: MaybeUninit::uninit(),
            advertise_handles: MaybeUninit::uninit(),
            inner: MaybeUninit::uninit(),
        }
    }
}

/// Create a new instance of the BLE host using the provided controller implementation and
/// the resource configuration
pub fn new<
    'd,
    C: Controller,
    const CONNS: usize,
    const CHANNELS: usize,
    const L2CAP_MTU: usize,
    const ADV_SETS: usize,
>(
    controller: C,
    resources: &'d mut HostResources<C, CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>,
) -> Builder<'d, C> {
    unsafe fn transmute_slice<T>(x: &mut [T]) -> &'static mut [T] {
        core::mem::transmute(x)
    }

    // Safety:
    // - HostResources has the same lifetime as the returned Builder.
    // - Internal lifetimes are elided (made 'static) to simplify API usage
    // - This _should_ be OK, because there are no references held to the resources
    //   when the stack is shut down.
    use crate::packet_pool::GlobalPacketPool;
    let rx_pool: &'d dyn GlobalPacketPool<'d> = &*resources.rx_pool.write(PacketPool::new(resources.qos));
    let rx_pool = unsafe {
        core::mem::transmute::<&'d dyn GlobalPacketPool<'d>, &'static dyn GlobalPacketPool<'static>>(rx_pool)
    };

    let connections = &mut *resources.connections.write([ConnectionStorage::DISCONNECTED; CONNS]);
    let connections = unsafe { transmute_slice(connections) };
    let channels = &mut *resources.channels.write([ChannelStorage::DISCONNECTED; CHANNELS]);
    let channels = unsafe { transmute_slice(channels) };
    let channels_rx = &mut *resources.channels_rx.write([PacketChannel::NEW; CHANNELS]);
    let channels_rx = unsafe { transmute_slice(channels_rx) };
    let sar = &mut *resources.sar.write([const { None }; CONNS]);
    let sar = unsafe { transmute_slice(sar) };
    let advertise_handles = &mut *resources.advertise_handles.write([AdvHandleState::None; ADV_SETS]);
    let advertise_handles = unsafe { transmute_slice(advertise_handles) };
    let host = BleHost::new(
        controller,
        rx_pool,
        connections,
        channels,
        channels_rx,
        sar,
        advertise_handles,
    );

    let host = &mut *resources.inner.write(host);
    let host = unsafe { core::mem::transmute::<&mut BleHost<'_, C>, &'d mut BleHost<'d, C>>(host) };
    Builder { host }
}

/// Type for configuring the BLE host.
pub struct Builder<'d, C: Controller> {
    host: &'d mut BleHost<'d, C>,
}

impl<'d, C: Controller> Builder<'d, C> {
    /// Set the random address used by this host.
    pub fn set_random_address(self, address: Address) -> Self {
        self.host.address.replace(address);
        self
    }

    /// Build the stack.
    #[cfg(all(feature = "central", feature = "peripheral"))]
    pub fn build(self) -> (Stack<'d, C>, Peripheral<'d, C>, Central<'d, C>, Runner<'d, C>) {
        (
            Stack::new(self.host),
            Peripheral::new(self.host),
            Central::new(self.host),
            Runner::new(self.host),
        )
    }

    /// Build the stack.
    #[cfg(all(not(feature = "central"), feature = "peripheral"))]
    pub fn build(self) -> (Stack<'d, C>, Peripheral<'d, C>, Runner<'d, C>) {
        (
            Stack::new(self.host),
            Peripheral::new(self.host),
            Runner::new(self.host),
        )
    }

    /// Build the stack.
    #[cfg(all(feature = "central", not(feature = "peripheral")))]
    pub fn build(self) -> (Stack<'d, C>, Central<'d, C>, Runner<'d, C>) {
        (Stack::new(self.host), Central::new(self.host), Runner::new(self.host))
    }
}

/// Handle to the BLE stack.
pub struct Stack<'d, C> {
    host: &'d BleHost<'d, C>,
}

impl<'d, C> Stack<'d, C> {
    pub(crate) fn new(host: &'d BleHost<'d, C>) -> Self {
        Self { host }
    }
}

impl<'d, C> Clone for Stack<'d, C> {
    fn clone(&self) -> Self {
        Self { host: self.host }
    }
}

impl<'d, C> Copy for Stack<'d, C> {}
