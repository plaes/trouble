//! BleHost
//!
//! The host module contains the main entry point for the TrouBLE host.
use core::cell::RefCell;
use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::task::Poll;

use bt_hci::cmd::controller_baseband::{
    HostBufferSize, HostNumberOfCompletedPackets, Reset, SetControllerToHostFlowControl, SetEventMask,
};
use bt_hci::cmd::le::{
    LeConnUpdate, LeCreateConnCancel, LeReadBufferSize, LeReadFilterAcceptListSize, LeSetAdvEnable, LeSetEventMask,
    LeSetExtAdvEnable, LeSetRandomAddr,
};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{blocking, Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::{Event, Vendor};
use bt_hci::param::{
    AddrKind, AdvHandle, AdvSet, BdAddr, ConnHandle, DisconnectReason, EventMask, LeConnRole, LeEventMask, Status,
};
#[cfg(feature = "controller-host-flow-control")]
use bt_hci::param::{ConnHandleCompletedPackets, ControllerToHostFlowControl};
use bt_hci::{ControllerToHostPacket, FromHciBytes, WriteHci};
use embassy_futures::select::{select3, select4, Either3, Either4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::waitqueue::WakerRegistration;
use futures::pin_mut;

use crate::channel_manager::{ChannelManager, ChannelStorage, PacketChannel};
use crate::command::CommandState;
use crate::connection_manager::{ConnectionManager, ConnectionStorage, DynamicConnectionManager, PacketGrant};
use crate::cursor::WriteCursor;
use crate::l2cap::sar::{PacketReassembly, SarType};
use crate::packet_pool::{AllocId, GlobalPacketPool};
use crate::pdu::Pdu;
use crate::types::l2cap::{
    L2capHeader, L2capSignal, L2capSignalHeader, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL,
};
use crate::{att, config, Address, BleHostError, Error};

/// A BLE Host.
///
/// The BleHost holds the runtime state of the host, and is the entry point
/// for all interactions with the controller.
///
/// The host performs connection management, l2cap channel management, and
/// multiplexes events and data across connections and l2cap channels.
pub(crate) struct BleHost<'d, T> {
    initialized: OnceLock<()>,
    metrics: RefCell<HostMetrics>,
    pub(crate) address: Option<Address>,
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<'d>,
    pub(crate) reassembly: PacketReassembly<'d>,
    pub(crate) channels: ChannelManager<'d, { config::L2CAP_RX_QUEUE_SIZE }>,
    #[cfg(feature = "gatt")]
    pub(crate) att_inbound: Channel<NoopRawMutex, (ConnHandle, Pdu<'d>), { config::L2CAP_RX_QUEUE_SIZE }>,
    pub(crate) rx_pool: &'d dyn GlobalPacketPool<'d>,
    pub(crate) outbound: Channel<NoopRawMutex, (ConnHandle, Pdu<'d>), { config::L2CAP_TX_QUEUE_SIZE }>,

    #[cfg(feature = "scan")]
    pub(crate) scanner: Channel<NoopRawMutex, Option<ScanReport>, 1>,
    pub(crate) advertise_state: AdvState<'d>,
    pub(crate) advertise_command_state: CommandState<bool>,
    pub(crate) connect_command_state: CommandState<bool>,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum AdvHandleState {
    None,
    Advertising(AdvHandle),
    Terminated(AdvHandle),
}

pub(crate) struct AdvInnerState<'d> {
    handles: &'d mut [AdvHandleState],
    waker: WakerRegistration,
}

pub(crate) struct AdvState<'d> {
    state: RefCell<AdvInnerState<'d>>,
}

impl<'d> AdvState<'d> {
    pub(crate) fn new(handles: &'d mut [AdvHandleState]) -> Self {
        Self {
            state: RefCell::new(AdvInnerState {
                handles,
                waker: WakerRegistration::new(),
            }),
        }
    }

    pub(crate) fn reset(&self) {
        let mut state = self.state.borrow_mut();
        for entry in state.handles.iter_mut() {
            *entry = AdvHandleState::None;
        }
        state.waker.wake();
    }

    // Terminate handle
    pub(crate) fn terminate(&self, handle: AdvHandle) {
        let mut state = self.state.borrow_mut();
        for entry in state.handles.iter_mut() {
            match entry {
                AdvHandleState::Advertising(h) if *h == handle => {
                    *entry = AdvHandleState::Terminated(handle);
                }
                _ => {}
            }
        }
        state.waker.wake();
    }

    pub(crate) fn len(&self) -> usize {
        let state = self.state.borrow();
        state.handles.len()
    }

    pub(crate) fn start(&self, sets: &[AdvSet]) {
        let mut state = self.state.borrow_mut();
        assert!(sets.len() <= state.handles.len());
        for handle in state.handles.iter_mut() {
            *handle = AdvHandleState::None;
        }

        for (idx, entry) in sets.iter().enumerate() {
            state.handles[idx] = AdvHandleState::Advertising(entry.adv_handle);
        }
    }

    pub async fn wait(&self) {
        poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            state.waker.register(cx.waker());

            let mut terminated = 0;
            for entry in state.handles.iter() {
                match entry {
                    AdvHandleState::Terminated(_) => {
                        terminated += 1;
                    }
                    AdvHandleState::None => {
                        terminated += 1;
                    }
                    _ => {}
                }
            }
            if terminated == state.handles.len() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// Host metrics
#[derive(Default, Clone)]
pub struct HostMetrics {
    pub connect_events: u32,
    pub disconnect_events: u32,
    pub rx_errors: u32,
}

impl<'d, T> BleHost<'d, T>
where
    T: Controller,
{
    /// Create a new instance of the BLE host.
    ///
    /// The host requires a HCI driver (a particular HCI-compatible controller implementing the required traits), and
    /// a reference to resources that are created outside the host but which the host is the only accessor of.
    pub(crate) fn new(
        controller: T,
        rx_pool: &'d dyn GlobalPacketPool<'d>,
        connections: &'d mut [ConnectionStorage],
        channels: &'d mut [ChannelStorage],
        channels_rx: &'d mut [PacketChannel<'d, { config::L2CAP_RX_QUEUE_SIZE }>],
        sar: &'d mut [SarType<'d>],
        advertise_handles: &'d mut [AdvHandleState],
    ) -> Self {
        Self {
            address: None,
            initialized: OnceLock::new(),
            metrics: RefCell::new(HostMetrics::default()),
            controller,
            connections: ConnectionManager::new(connections),
            reassembly: PacketReassembly::new(sar),
            channels: ChannelManager::new(rx_pool, channels, channels_rx),
            rx_pool,
            #[cfg(feature = "gatt")]
            att_inbound: Channel::new(),
            #[cfg(feature = "scan")]
            scanner: Channel::new(),
            advertise_state: AdvState::new(advertise_handles),
            advertise_command_state: CommandState::new(),
            connect_command_state: CommandState::new(),
            outbound: Channel::new(),
        }
    }

    /// Run a HCI command and return the response.
    pub(crate) async fn command<C>(&self, cmd: C) -> Result<C::Return, BleHostError<T::Error>>
    where
        C: SyncCmd,
        T: ControllerCmdSync<C>,
    {
        let _ = self.initialized.get().await;
        let ret = cmd.exec(&self.controller).await?;
        Ok(ret)
    }

    /// Run an async HCI command where the response will generate an event later.
    pub(crate) async fn async_command<C>(&self, cmd: C) -> Result<(), BleHostError<T::Error>>
    where
        C: AsyncCmd,
        T: ControllerCmdAsync<C>,
    {
        let _ = self.initialized.get().await;
        cmd.exec(&self.controller).await?;
        Ok(())
    }

    fn handle_connection(
        &self,
        status: Status,
        handle: ConnHandle,
        peer_addr_kind: AddrKind,
        peer_addr: BdAddr,
        role: LeConnRole,
    ) -> bool {
        match status.to_result() {
            Ok(_) => {
                if let Err(err) = self.connections.connect(handle, peer_addr_kind, peer_addr, role) {
                    warn!("Error establishing connection: {:?}", err);
                    return false;
                } else {
                    #[cfg(feature = "defmt")]
                    trace!(
                        "[host] connection with handle {:?} established to {:02x}",
                        handle,
                        peer_addr
                    );
                    let mut m = self.metrics.borrow_mut();
                    m.connect_events = m.connect_events.wrapping_add(1);
                }
            }
            Err(bt_hci::param::Error::ADV_TIMEOUT) => {
                self.advertise_state.reset();
            }
            Err(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER) => {
                warn!("[host] connect cancelled");
                self.connect_command_state.canceled();
            }
            Err(e) => {
                warn!("Error connection complete event: {:?}", e);
                self.connect_command_state.canceled();
            }
        }
        true
    }

    fn handle_acl(&self, acl: AclPacket<'_>) -> Result<(), Error> {
        if !self.connections.is_handle_connected(acl.handle()) {
            return Err(Error::Disconnected);
        }
        let (header, mut packet) = match acl.boundary_flag() {
            AclPacketBoundary::FirstFlushable => {
                let (header, data) = L2capHeader::from_hci_bytes(acl.data())?;

                // Ignore channels we don't support
                if header.channel < L2CAP_CID_DYN_START
                    && !(&[L2CAP_CID_LE_U_SIGNAL, L2CAP_CID_ATT].contains(&header.channel))
                {
                    warn!("[host] unsupported l2cap channel id {}", header.channel);
                    return Err(Error::NotSupported);
                }

                // Avoids using the packet buffer for signalling packets
                if header.channel == L2CAP_CID_LE_U_SIGNAL {
                    assert!(data.len() == header.length as usize);
                    self.channels.signal(acl.handle(), data)?;
                    return Ok(());
                }

                let Some(mut p) = self.rx_pool.alloc(AllocId::from_channel(header.channel)) else {
                    info!("No memory for packets on channel {}", header.channel);
                    return Err(Error::OutOfMemory);
                };
                p.as_mut()[..data.len()].copy_from_slice(data);

                if header.length as usize != data.len() {
                    self.reassembly.init(acl.handle(), header, p, data.len())?;
                    return Ok(());
                }
                (header, p)
            }
            // Next (potentially last) in a fragment
            AclPacketBoundary::Continuing => {
                // Get the existing fragment
                if let Some((header, p)) = self.reassembly.update(acl.handle(), acl.data())? {
                    (header, p)
                } else {
                    // Do not process yet
                    return Ok(());
                }
            }
            other => {
                warn!("Unexpected boundary flag: {:?}!", other);
                return Err(Error::NotSupported);
            }
        };

        match header.channel {
            L2CAP_CID_ATT => {
                // Handle ATT MTU exchange here since it doesn't strictly require
                // gatt to be enabled.
                if let Ok(att::AttReq::ExchangeMtu { mtu }) =
                    att::AttReq::decode(&packet.as_ref()[..header.length as usize])
                {
                    let mtu = self.connections.exchange_att_mtu(acl.handle(), mtu);

                    let rsp = att::AttRsp::ExchangeMtu { mtu };
                    let l2cap = L2capHeader {
                        channel: L2CAP_CID_ATT,
                        length: 3,
                    };

                    let mut w = WriteCursor::new(packet.as_mut());
                    w.write_hci(&l2cap)?;
                    w.write(rsp)?;

                    trace!("[host] agreed att MTU of {}", mtu);
                    let len = w.len();
                    if let Err(e) = self.outbound.try_send((acl.handle(), Pdu::new(packet, len))) {
                        return Err(Error::OutOfMemory);
                    }
                } else if let Ok(att::AttRsp::ExchangeMtu { mtu }) =
                    att::AttRsp::decode(&packet.as_ref()[..header.length as usize])
                {
                    trace!("[host] remote agreed att MTU of {}", mtu);
                    self.connections.exchange_att_mtu(acl.handle(), mtu);
                } else {
                    #[cfg(feature = "gatt")]
                    if let Err(e) = self
                        .att_inbound
                        .try_send((acl.handle(), Pdu::new(packet, header.length as usize)))
                    {
                        return Err(Error::OutOfMemory);
                    }

                    #[cfg(not(feature = "gatt"))]
                    return Err(Error::NotSupported);
                }
            }
            L2CAP_CID_LE_U_SIGNAL => {
                panic!("le signalling channel was fragmented, impossible!");
            }
            other if other >= L2CAP_CID_DYN_START => match self.channels.dispatch(header, packet) {
                Ok(_) => {}
                Err(e) => {
                    warn!("Error dispatching l2cap packet to channel: {:?}", e);
                    return Err(e);
                }
            },
            chan => {
                debug!(
                    "[host] conn {:?} attempted to use unsupported l2cap channel {}, ignoring",
                    acl.handle(),
                    chan
                );
                return Ok(());
            }
        }
        Ok(())
    }

    pub(crate) async fn run_with_handler<F: Fn(&Vendor)>(&self, vendor_handler: F) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        const MAX_HCI_PACKET_LEN: usize = 259;

        // Control future that initializes system and handles controller changes.
        let control_fut = async {
            Reset::new().exec(&self.controller).await?;

            if let Some(addr) = self.address {
                LeSetRandomAddr::new(addr.addr).exec(&self.controller).await?;
            }

            SetEventMask::new(
                EventMask::new()
                    .enable_le_meta(true)
                    .enable_conn_request(true)
                    .enable_conn_complete(true)
                    .enable_hardware_error(true)
                    .enable_disconnection_complete(true),
            )
            .exec(&self.controller)
            .await?;

            LeSetEventMask::new(
                LeEventMask::new()
                    .enable_le_conn_complete(true)
                    .enable_le_enhanced_conn_complete(true)
                    .enable_le_adv_set_terminated(true)
                    .enable_le_adv_report(true)
                    .enable_le_scan_timeout(true)
                    .enable_le_ext_adv_report(true),
            )
            .exec(&self.controller)
            .await?;

            let ret = LeReadFilterAcceptListSize::new().exec(&self.controller).await?;
            info!("[host] filter accept list size: {}", ret);

            let ret = LeReadBufferSize::new().exec(&self.controller).await?;
            info!("[host] setting txq to {}", ret.total_num_le_acl_data_packets as usize);
            self.connections
                .set_link_credits(ret.total_num_le_acl_data_packets as usize);

            info!(
                "[host] configuring host buffers ({} packets of size {})",
                config::L2CAP_RX_PACKET_POOL_SIZE,
                self.rx_pool.mtu()
            );
            HostBufferSize::new(
                self.rx_pool.mtu() as u16,
                0,
                config::L2CAP_RX_PACKET_POOL_SIZE as u16,
                0,
            )
            .exec(&self.controller)
            .await?;

            #[cfg(feature = "controller-host-flow-control")]
            {
                info!("[host] enabling flow control");
                SetControllerToHostFlowControl::new(ControllerToHostFlowControl::AclOnSyncOff)
                    .exec(&self.controller)
                    .await?;
            }

            let _ = self.initialized.init(());
            info!("[host] initialized");

            loop {
                match select4(
                    poll_fn(|cx| self.connections.poll_disconnecting(Some(cx))),
                    poll_fn(|cx| self.channels.poll_disconnecting(Some(cx))),
                    poll_fn(|cx| self.connect_command_state.poll_cancelled(cx)),
                    poll_fn(|cx| self.advertise_command_state.poll_cancelled(cx)),
                )
                .await
                {
                    Either4::First(request) => {
                        self.command(Disconnect::new(request.handle(), request.reason()))
                            .await?;
                        request.confirm();
                    }
                    Either4::Second(request) => {
                        let mut grant = self.acl(request.handle(), 1).await?;
                        request.send(&mut grant).await?;
                        request.confirm();
                    }
                    Either4::Third(_) => {
                        // trace!("[host] cancelling create connection");
                        if self.command(LeCreateConnCancel::new()).await.is_err() {
                            // Signal to ensure no one is stuck
                            self.connect_command_state.canceled();
                        }
                    }
                    Either4::Fourth(ext) => {
                        trace!("[host] disabling advertising");
                        if ext {
                            self.command(LeSetExtAdvEnable::new(false, &[])).await?
                        } else {
                            self.command(LeSetAdvEnable::new(false)).await?
                        }
                        self.advertise_command_state.canceled();
                    }
                }
            }
        };
        pin_mut!(control_fut);

        let tx_fut = async {
            loop {
                let (conn, pdu) = self.outbound.receive().await;
                match self.acl(conn, 1).await {
                    Ok(mut sender) => {
                        if let Err(e) = sender.send(pdu.as_ref()).await {
                            warn!("[host] error sending outbound pdu");
                            return Err(e);
                        }
                    }
                    Err(e) => {
                        warn!("[host] error requesting sending outbound pdu");
                        return Err(e);
                    }
                }
            }
        };
        pin_mut!(tx_fut);

        let rx_fut = async {
            loop {
                // Task handling receiving data from the controller.
                let mut rx = [0u8; MAX_HCI_PACKET_LEN];
                let result = self.controller.read(&mut rx).await;
                match result {
                    Ok(ControllerToHostPacket::Acl(acl)) => match self.handle_acl(acl) {
                        Ok(_) => {
                            #[cfg(feature = "controller-host-flow-control")]
                            if let Err(e) =
                                HostNumberOfCompletedPackets::new(&[ConnHandleCompletedPackets::new(acl.handle(), 1)])
                                    .exec(&self.controller)
                                    .await
                            {
                                // Only serious error if it's supposed to be connected
                                if self.connections.get_connected_handle(acl.handle()).is_some() {
                                    error!("[host] error performing flow control on {:?}", acl.handle());
                                    return Err(e.into());
                                }
                            }
                        }
                        Err(e) => {
                            #[cfg(feature = "controller-host-flow-control")]
                            if let Err(e) =
                                HostNumberOfCompletedPackets::new(&[ConnHandleCompletedPackets::new(acl.handle(), 1)])
                                    .exec(&self.controller)
                                    .await
                            {
                                // Only serious error if it's supposed to be connected
                                if self.connections.get_connected_handle(acl.handle()).is_some() {
                                    error!("[host] error performing flow control on {:?}", acl.handle());
                                    return Err(e.into());
                                }
                            }

                            warn!(
                                "[host] encountered error processing ACL data for {:?}: {:?}",
                                acl.handle(),
                                e
                            );

                            if let Error::Disconnected = e {
                                warn!("[host] requesting {:?} to be disconnected", acl.handle());
                                let _ = self
                                    .command(Disconnect::new(
                                        acl.handle(),
                                        DisconnectReason::RemoteUserTerminatedConn,
                                    ))
                                    .await;
                                self.connections.log_status(true);
                            }

                            let mut m = self.metrics.borrow_mut();
                            m.rx_errors = m.rx_errors.wrapping_add(1);
                        }
                    },
                    Ok(ControllerToHostPacket::Event(event)) => match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(e) => {
                                if !self.handle_connection(e.status, e.handle, e.peer_addr_kind, e.peer_addr, e.role) {
                                    let _ = self
                                        .command(Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        ))
                                        .await;
                                    self.connect_command_state.canceled();
                                }
                            }
                            LeEvent::LeEnhancedConnectionComplete(e) => {
                                if !self.handle_connection(e.status, e.handle, e.peer_addr_kind, e.peer_addr, e.role) {
                                    let _ = self
                                        .command(Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        ))
                                        .await;
                                    self.connect_command_state.canceled();
                                }
                            }
                            LeEvent::LeScanTimeout(_) => {
                                #[cfg(feature = "scan")]
                                let _ = self.scanner.try_send(None);
                            }
                            LeEvent::LeAdvertisingSetTerminated(set) => {
                                self.advertise_state.terminate(set.adv_handle);
                            }
                            LeEvent::LeExtendedAdvertisingReport(data) => {
                                #[cfg(feature = "scan")]
                                let _ = self
                                    .scanner
                                    .try_send(Some(ScanReport::new(data.reports.num_reports, &data.reports.bytes)));
                            }
                            LeEvent::LeAdvertisingReport(data) => {
                                #[cfg(feature = "scan")]
                                let _ = self
                                    .scanner
                                    .try_send(Some(ScanReport::new(data.reports.num_reports, &data.reports.bytes)));
                            }
                            _ => {
                                warn!("Unknown LE event!");
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            let handle = e.handle;
                            if let Err(e) = e.status.to_result() {
                                info!("[host] disconnection event on handle {}, status: {:?}", handle.raw(), e);
                            } else if let Err(e) = e.reason.to_result() {
                                info!("[host] disconnection event on handle {}, reason: {:?}", handle.raw(), e);
                            } else {
                                info!("[host] disconnection event on handle {}", handle.raw());
                            }
                            let _ = self.connections.disconnected(handle);
                            let _ = self.channels.disconnected(handle);
                            self.reassembly.disconnected(handle);
                            let mut m = self.metrics.borrow_mut();
                            m.disconnect_events = m.disconnect_events.wrapping_add(1);
                        }
                        Event::NumberOfCompletedPackets(c) => {
                            // Explicitly ignoring for now
                            for entry in c.completed_packets.iter() {
                                if let (Ok(handle), Ok(completed)) = (entry.handle(), entry.num_completed_packets()) {
                                    let _ = self.connections.confirm_sent(handle, completed as usize);
                                }
                            }
                        }
                        Event::Vendor(vendor) => {
                            vendor_handler(&vendor);
                        }
                        // Ignore
                        _ => {}
                    },
                    // Ignore
                    Ok(_) => {}
                    Err(e) => {
                        return Err(BleHostError::Controller(e));
                    }
                }
            }
        };
        pin_mut!(rx_fut);

        // info!("Entering select loop");
        match select3(&mut control_fut, &mut rx_fut, &mut tx_fut).await {
            Either3::First(result) => {
                trace!("[host] control_fut exit");
                result
            }
            Either3::Second(result) => {
                trace!("[host] rx_fut exit");
                result
            }
            Either3::Third(result) => {
                trace!("[host] tx_fut exit");
                result
            }
        }
    }

    // Request to send n ACL packets to the HCI controller for a connection
    pub(crate) async fn acl(&self, handle: ConnHandle, n: u16) -> Result<AclSender<'_, 'd, T>, BleHostError<T::Error>> {
        let grant = poll_fn(|cx| self.connections.poll_request_to_send(handle, n as usize, Some(cx))).await?;
        Ok(AclSender {
            controller: &self.controller,
            handle,
            grant,
        })
    }

    // Request to send n ACL packets to the HCI controller for a connection
    pub(crate) fn try_acl(&self, handle: ConnHandle, n: u16) -> Result<AclSender<'_, 'd, T>, BleHostError<T::Error>> {
        let grant = match self.connections.poll_request_to_send(handle, n as usize, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => {
                return Err(Error::Busy.into());
            }
        };
        Ok(AclSender {
            controller: &self.controller,
            handle,
            grant,
        })
    }

    /// Read current host metrics
    pub fn metrics(&self) -> HostMetrics {
        let m = self.metrics.borrow_mut().clone();
        m
    }

    /// Log status information of the host
    pub fn log_status(&self, verbose: bool) {
        let m = self.metrics.borrow();
        debug!("[host] connect events: {}", m.connect_events);
        debug!("[host] disconnect events: {}", m.disconnect_events);
        debug!("[host] rx errors: {}", m.rx_errors);
        self.connections.log_status(verbose);
        self.channels.log_status(verbose);
    }
}

/// Runs the host with the given controller.
pub struct Runner<'d, C: Controller> {
    host: &'d BleHost<'d, C>,
}

impl<'d, C: Controller> Runner<'d, C> {
    pub(crate) fn new(host: &'d BleHost<'d, C>) -> Self {
        Self { host }
    }

    /// Run the host.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        self.host.run_with_handler(|_| {}).await
    }

    /// Run the host with a vendor event handler for custom events.
    pub async fn run_with_handler<F: Fn(&Vendor)>(&mut self, vendor_handler: F) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        self.host.run_with_handler(vendor_handler).await
    }
}

pub struct AclSender<'a, 'd, T: Controller> {
    pub(crate) controller: &'a T,
    pub(crate) handle: ConnHandle,
    pub(crate) grant: PacketGrant<'a, 'd>,
}

impl<'a, 'd, T: Controller> AclSender<'a, 'd, T> {
    pub(crate) fn try_send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>>
    where
        T: blocking::Controller,
    {
        let acl = AclPacket::new(
            self.handle,
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            pdu,
        );
        // info!("Sent ACL {:?}", acl);
        match self.controller.try_write_acl_data(&acl) {
            Ok(result) => {
                self.grant.confirm(1);
                Ok(result)
            }
            Err(blocking::TryError::Busy) => {
                warn!("hci: acl data send busy");
                Err(Error::Busy.into())
            }
            Err(blocking::TryError::Error(e)) => Err(BleHostError::Controller(e)),
        }
    }

    pub(crate) async fn send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>> {
        let acl = AclPacket::new(
            self.handle,
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            pdu,
        );
        self.controller
            .write_acl_data(&acl)
            .await
            .map_err(BleHostError::Controller)?;
        self.grant.confirm(1);
        Ok(())
    }

    pub(crate) async fn signal<D: L2capSignal>(
        &mut self,
        identifier: u8,
        signal: &D,
        p_buf: &mut [u8],
    ) -> Result<(), BleHostError<T::Error>> {
        //trace!(
        //    "[l2cap] sending control signal (req = {}) signal: {:?}",
        //    identifier,
        //    signal
        //);
        let header = L2capSignalHeader {
            identifier,
            code: D::code(),
            length: signal.size() as u16,
        };
        let l2cap = L2capHeader {
            channel: D::channel(),
            length: header.size() as u16 + header.length,
        };

        let mut w = WriteCursor::new(p_buf);
        w.write_hci(&l2cap)?;
        w.write_hci(&header)?;
        w.write_hci(signal)?;

        self.send(w.finish()).await?;

        Ok(())
    }
}

/// A type to delay the drop handler invocation.
#[must_use = "to delay the drop handler invocation to the end of the scope"]
pub struct OnDrop<F: FnOnce()> {
    f: MaybeUninit<F>,
}

impl<F: FnOnce()> OnDrop<F> {
    /// Create a new instance.
    pub fn new(f: F) -> Self {
        Self { f: MaybeUninit::new(f) }
    }

    /// Prevent drop handler from running.
    pub fn defuse(self) {
        core::mem::forget(self)
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}
