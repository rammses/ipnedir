use crate::model::CollectError;
use std::{
    io,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
pub fn dump(kind: u16, payload: &[u8]) -> Result<Vec<u8>, CollectError> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQUENCE: AtomicU32 = AtomicU32::new(1);
    let seq = SEQUENCE.fetch_add(2, Ordering::Relaxed).max(1);
    dump_with(&mut native::RouteTransport::default(), kind, payload, seq)
}

pub(super) struct Datagram {
    pub bytes: Vec<u8>,
    pub sender_family: u16,
    pub sender_pid: u32,
    pub sender_len: usize,
    pub flags: i32,
}

pub(super) trait Transport {
    fn now(&self) -> Instant;
    fn send(&mut self, request: &[u8], deadline: Instant) -> io::Result<()>;
    fn receive(&mut self, deadline: Instant) -> io::Result<Datagram>;
}

pub(super) fn datagram_capacity(len: usize) -> Result<usize, CollectError> {
    if len == 0 || len > 4 * 1024 * 1024 {
        Err(CollectError(
            "empty netlink datagram or exceeds 4 MiB".into(),
        ))
    } else {
        Ok(len)
    }
}

pub(super) fn dump_with(
    io: &mut impl Transport,
    kind: u16,
    payload: &[u8],
    mut seq: u32,
) -> Result<Vec<u8>, CollectError> {
    // rtnetlink.h groups message families in fours: NEW/DEL/GET/SET.
    // This transport only sends GET dumps, never mutation requests.
    if seq == 0 || kind < 18 || kind % 4 != 2 {
        return Err(CollectError("invalid netlink request kind/sequence".into()));
    }
    let deadline = io.now() + Duration::from_secs(1);
    let mut total = 0_usize;
    for attempt in 0..2 {
        let request = request(kind, payload, seq)?;
        loop {
            check_deadline(io.now(), deadline)?;
            match io.send(&request, deadline) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(CollectError(format!("netlink send: {error}"))),
            }
        }
        let mut output = Vec::new();
        loop {
            check_deadline(io.now(), deadline)?;
            let packet = match io.receive(deadline) {
                Ok(packet) => packet,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(CollectError(format!("netlink receive: {error}"))),
            };
            check_deadline(io.now(), deadline)?;
            datagram_capacity(packet.bytes.len())?;
            total = total
                .checked_add(packet.bytes.len())
                .filter(|&n| n <= 16 * 1024 * 1024)
                .ok_or_else(|| CollectError("netlink dump exceeds 16 MiB".into()))?;
            let batch = consume(&packet, seq, kind - 2, &mut output)?;
            check_deadline(io.now(), deadline)?;
            match batch {
                Batch::More => {}
                Batch::Done => return Ok(output),
                Batch::Interrupted if attempt == 0 => break,
                Batch::Interrupted => {
                    return Err(CollectError("netlink dump interrupted twice".into()));
                }
            }
        }
        // A retry uses a fresh socket/sequence, discards partial data, and keeps
        // both the original deadline and the whole-operation allocation cap.
        seq = seq.wrapping_add(1).max(1);
    }
    Err(CollectError("netlink dump incomplete".into()))
}

fn check_deadline(now: Instant, deadline: Instant) -> Result<(), CollectError> {
    if now >= deadline {
        Err(CollectError("netlink whole-dump deadline exceeded".into()))
    } else {
        Ok(())
    }
}

fn request(kind: u16, payload: &[u8], seq: u32) -> Result<Vec<u8>, CollectError> {
    let len = payload
        .len()
        .checked_add(16)
        .ok_or_else(|| CollectError("netlink request length overflow".into()))?;
    datagram_capacity(len)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| CollectError("netlink request allocation failed".into()))?;
    bytes.extend((len as u32).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(0x301_u16.to_ne_bytes()); // REQUEST | ROOT | MATCH (dump)
    bytes.extend(seq.to_ne_bytes());
    bytes.extend(0_u32.to_ne_bytes());
    bytes.extend(payload);
    Ok(bytes)
}

enum Batch {
    More,
    Done,
    Interrupted,
}

fn consume(
    packet: &Datagram,
    seq: u32,
    expected: u16,
    output: &mut Vec<u8>,
) -> Result<Batch, CollectError> {
    // sockaddr_nl, not nlmsghdr.nlmsg_pid, establishes kernel provenance.
    if packet.sender_family != 16 || packet.sender_pid != 0 || packet.sender_len != 12 {
        return Err(CollectError("invalid netlink sender address".into()));
    }
    if packet.flags & 0x20 != 0 {
        // Linux MSG_TRUNC (portable wire constant)
        return Err(CollectError("truncated netlink datagram".into()));
    }
    let mut done = false;
    let mut interrupted = false;
    for_messages(&packet.bytes, |msg| {
        if msg.seq != seq {
            return Err(CollectError("unexpected netlink sequence".into()));
        }
        if done {
            return Err(CollectError("netlink message after completion".into()));
        }
        interrupted |= msg.flags & 0x10 != 0; // NLM_F_DUMP_INTR on ANY message
        if msg.flags & 0x20 != 0 {
            // NLM_F_DUMP_FILTERED is not an exhaustive dump.
            return Err(CollectError(
                "filtered netlink inventory is incomplete".into(),
            ));
        }
        match msg.kind {
            2 => {
                if msg.payload.len() < 20 || u32_ne(&msg.payload[4..]) < 16 {
                    return Err(CollectError("malformed netlink ERROR/ACK".into()));
                }
                let error = i32::from_ne_bytes(msg.payload[..4].try_into().expect("checked errno"));
                if error != 0 {
                    return Err(CollectError(format!("netlink ERROR {error}")));
                }
            }
            3 => {
                if !msg.payload.is_empty() {
                    if msg.payload.len() < 4 {
                        return Err(CollectError("malformed netlink DONE".into()));
                    }
                    let error =
                        i32::from_ne_bytes(msg.payload[..4].try_into().expect("checked errno"));
                    if error != 0 {
                        return Err(CollectError(format!("netlink DONE error {error}")));
                    }
                }
                done = true;
            }
            4 => {
                return Err(CollectError(
                    "netlink overrun (incomplete inventory)".into(),
                ));
            }
            kind if kind == expected => {
                if msg.flags & 2 == 0 {
                    return Err(CollectError("netlink dump reply is not multipart".into()));
                }
                output
                    .try_reserve_exact(msg.framed.len())
                    .map_err(|_| CollectError("netlink dump allocation failed".into()))?;
                output.extend(msg.framed);
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(if interrupted {
        Batch::Interrupted
    } else if done {
        Batch::Done
    } else {
        Batch::More
    })
}

// Linux UAPI linux/netlink.h: nlmsghdr is 16 bytes; lengths include the
// header but not four-byte alignment padding. Read copies, never cast bytes.
pub(super) struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
    pub framed: &'a [u8],
}

pub(super) fn u16_ne(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().expect("checked u16 field"))
}

pub(super) fn u32_ne(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().expect("checked u32 field"))
}

pub(super) fn aligned_record(
    bytes: &[u8],
    len: usize,
    minimum: usize,
) -> Result<(&[u8], &[u8]), CollectError> {
    let padded = len.checked_add(3).map(|n| n & !3);
    match padded {
        Some(padded) if len >= minimum && padded <= bytes.len() => {
            Ok((&bytes[..padded], &bytes[padded..]))
        }
        _ => Err(CollectError(
            "malformed native record length/alignment".into(),
        )),
    }
}

pub(super) fn for_messages(
    mut bytes: &[u8],
    mut visit: impl FnMut(Message<'_>) -> Result<(), CollectError>,
) -> Result<(), CollectError> {
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(CollectError("short netlink header".into()));
        }
        let len = u32_ne(bytes) as usize;
        let (framed, rest) = aligned_record(bytes, len, 16)?;
        visit(Message {
            kind: u16_ne(&bytes[4..]),
            flags: u16_ne(&bytes[6..]),
            seq: u32_ne(&bytes[8..]),
            payload: &bytes[16..len],
            framed,
        })?;
        bytes = rest;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) mod native {
    use super::{Datagram, Transport, datagram_capacity};
    use std::{
        io, mem,
        os::fd::{AsRawFd, OwnedFd},
        time::Instant,
    };

    // Verified against linux/netlink.h and libc0.2.191's exported UAPI.
    const _: () = assert!(mem::size_of::<libc::sockaddr_nl>() == 12);

    pub(crate) struct RouteSocket {
        pub(crate) fd: OwnedFd,
    }

    impl RouteSocket {
        pub(crate) fn open() -> io::Result<Self> {
            let fd = super::super::owned_socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )?;
            // SAFETY: sockaddr_nl has integer fields/padding only; zero
            // initializes pid/groups/pad, requesting a fresh unicast port.
            let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: fd is owned/live, address points to a complete initialized
            // libc sockaddr_nl for the target ABI, with its exact byte length.
            let result = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd }) // bind failure also drops fd via RAII.
        }
    }

    #[derive(Default)]
    pub(super) struct RouteTransport {
        socket: Option<RouteSocket>,
    }

    fn wait(fd: &OwnedFd, events: i16, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            let millis = remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: one initialized, writable pollfd remains live for poll;
            // borrowed fd ownership is unchanged. Timeout is finite and derived
            // from the unchanged whole-dump deadline, never a fresh second.
            let result = unsafe { libc::poll(&mut pollfd, 1, millis) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if result == 0 {
                continue;
            }
            if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("netlink poll error/hangup"));
            }
            if pollfd.revents & events != 0 {
                return Ok(());
            }
        }
    }

    fn recv(
        fd: &OwnedFd,
        bytes: &mut [u8],
        flags: i32,
    ) -> io::Result<(usize, libc::sockaddr_nl, usize, i32)> {
        // SAFETY: sockaddr_nl and msghdr are libc C POD layouts with valid
        // all-zero representations (including null pointers and zero lengths).
        let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
        // SAFETY: initialized below before recvmsg; zero control fields mean
        // no ancillary data buffer. No references into wire bytes are created.
        let mut header: libc::msghdr = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        header.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        header.msg_namelen = mem::size_of_val(&sender) as libc::socklen_t;
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        // SAFETY: fd is live; sender/header/iovec/buffer are exclusively
        // writable and live for the syscall, with exact capacities. DONTWAIT
        // prevents an unbounded receive even after a readiness race. TRUNC in
        // the PEEK call returns the datagram size without writing beyond iov.
        let len = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut header, flags | libc::MSG_DONTWAIT) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            len as usize,
            sender,
            header.msg_namelen as usize,
            header.msg_flags,
        ))
    }

    impl Transport for RouteTransport {
        fn now(&self) -> Instant {
            Instant::now()
        }

        fn send(&mut self, request: &[u8], deadline: Instant) -> io::Result<()> {
            // The calling thread owns a fresh bound socket on EACH attempt.
            // Close any interrupted-dump socket before constructing its replacement.
            self.socket.take();
            self.socket = Some(RouteSocket::open()?);
            let fd = &self.socket.as_ref().expect("new socket").fd;
            // SAFETY: sockaddr_nl is integer POD; kernel destination pid/groups0.
            let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            loop {
                wait(fd, libc::POLLOUT, deadline)?;
                // SAFETY: the read-only request slice and initialized destination
                // remain valid for the call; all lengths are exact. DONTWAIT
                // keeps the fresh socket send bounded by wait/deadline.
                let result = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        request.as_ptr().cast(),
                        request.len(),
                        libc::MSG_DONTWAIT,
                        (&kernel as *const libc::sockaddr_nl).cast(),
                        mem::size_of_val(&kernel) as libc::socklen_t,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(error);
                }
                if result as usize != request.len() {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                return Ok(());
            }
        }

        fn receive(&mut self, deadline: Instant) -> io::Result<Datagram> {
            let fd = &self.socket.as_ref().ok_or(io::ErrorKind::NotConnected)?.fd;
            loop {
                wait(fd, libc::POLLIN, deadline)?;
                let mut probe = [0_u8; 1];
                let size = match recv(fd, &mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                    Ok((size, _, _, _)) => size,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                };
                // Validate the peeked size BEFORE any size-dependent allocation.
                let size = datagram_capacity(size)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(size)
                    .map_err(|_| io::Error::other("netlink datagram allocation failed"))?;
                bytes.resize(size, 0);
                let (len, sender, sender_len, flags) = match recv(fd, &mut bytes, 0) {
                    Ok(result) => result,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                };
                if len > bytes.len() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                bytes.truncate(len);
                return Ok(Datagram {
                    bytes,
                    sender_family: sender.nl_family,
                    sender_pid: sender.nl_pid,
                    sender_len,
                    flags,
                });
            }
        }
    }
}
