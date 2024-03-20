#![no_std]
#![no_main]

mod bindings;
use bindings::{ethhdr, iphdr, udphdr};
use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use xdp_udp_echors_common::BackendPorts;

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

#[map(name = "BACKEND_PORTS")]
static mut BACKEND_PORTS: HashMap<u16, BackendPorts> =
    HashMap::<u16, BackendPorts>::with_max_entries(10, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr: *const T = ptr_at(ctx, offset)?;
    Some(ptr as *mut T)
}

#[xdp]
pub fn xdp_udp_echors(ctx: XdpContext) -> u32 {
    match try_xdp_udp_echors(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_udp_echors(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "received a UDP packet");
    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let dport = unsafe { u16::from_be((*udp).dest) };

    // Check if we have a backend for this port
    let backends = match unsafe { BACKEND_PORTS.get(&dport) } {
        Some(backends) => {
            info!(&ctx, "FOUND backends for port");
            backends
        }
        None => {
            info!(&ctx, "NO backends for this port");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if backends.index > backends.ports.len() - 1 {
        return Ok(xdp_action::XDP_ABORTED);
    }

    // Update the destination port for the packet to redirect to to a different backend
    let new_dport = backends.ports[backends.index];
    unsafe { (*udp).dest = u16::from_be(new_dport) };

    // Note: We aren't updating any checksums here.
    // https://docs.aya-rs.dev/
    info!(&ctx, "redirected port {} to {}", dport, new_dport);

    let mut new_backends = BackendPorts {
        ports: backends.ports,
        index: backends.index + 1,
    };

    if new_backends.index > new_backends.ports.len() - 1
        || new_backends.ports[new_backends.index] == 0
    {
        new_backends.index = 0;
    }

    match unsafe { BACKEND_PORTS.insert(&dport, &new_backends, 0) } {
        Ok(_) => {
            info!(&ctx, "index updated for port {}", dport);
            Ok(xdp_action::XDP_PASS)
        }
        Err(err) => {
            info!(&ctx, "error inserting index update: {}", err);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
