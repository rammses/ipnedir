use std::{net::IpAddr, time::Duration};

use ureq::{
    config::{Config, IpFamily},
    tls::{RootCerts, TlsConfig, TlsProvider},
};

use crate::model::Family;

pub(super) fn config(family: Family) -> Config {
    Config::builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .ip_family(match family {
            Family::V4 => IpFamily::Ipv4Only,
            Family::V6 => IpFamily::Ipv6Only,
        })
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::Rustls)
                .root_certs(RootCerts::WebPki)
                .disable_verification(false)
                .build(),
        )
        .max_response_header_size(8192)
        .timeout_connect(Some(Duration::from_millis(500)))
        .timeout_recv_response(Some(Duration::from_millis(500)))
        .timeout_recv_body(Some(Duration::from_millis(500)))
        .build()
}

pub(super) fn parse_body(family: Family, body: &[u8]) -> Option<IpAddr> {
    if body.len() > 128 {
        return None;
    }
    std::str::from_utf8(body)
        .ok()?
        .trim_ascii()
        .parse::<IpAddr>()
        .ok()
        .filter(|ip| match family {
            Family::V4 => ip.is_ipv4(),
            Family::V6 => ip.is_ipv6(),
        })
}

pub(super) fn response_ip(status: u16, family: Family, body: &[u8]) -> Option<IpAddr> {
    if status != 200 {
        return None;
    }
    parse_body(family, body)
}

/// Performs one lookup. The caller must run this entire function in its lookup worker.
pub fn lookup(family: Family) -> Option<IpAddr> {
    let endpoint = match family {
        Family::V4 => "https://ipv4.icanhazip.com/",
        Family::V6 => "https://ipv6.icanhazip.com/",
    };
    // All client, resolver, TLS and response state is created and dropped here, not on main.
    let agent = ureq::Agent::new_with_config(config(family));
    let mut response = agent.get(endpoint).call().ok()?;
    let status = response.status().as_u16();
    if status != 200 {
        return None;
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(128)
        .read_to_vec()
        .ok()?;
    response_ip(status, family, &body)
}
