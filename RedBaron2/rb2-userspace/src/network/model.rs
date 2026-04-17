use chrono::SecondsFormat;
use log::info;
use serde_json::{Value, json};

use crate::misc::{get_hostname, get_machine_id};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
    Unknown,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonFields {
    pub interface: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub transport: &'static str,
    pub direction: Direction,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    pub common: CommonFields,
    pub query_name: String,
    pub query_type: String,
    pub query_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEvent {
    pub common: CommonFields,
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub http_version: Option<String>,
    pub request_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: String,
    pub tls_library: &'static str,
    pub truncated: bool,
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub http_version: Option<String>,
    pub request_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedNetworkEvent {
    Dns(DnsEvent),
    Http(HttpEvent),
    Https(HttpsEvent),
}

impl ParsedNetworkEvent {
    pub fn log(&self) {
        match self {
            Self::Dns(event) => info!(target: "rb2_network", "{}", event.to_json("dns")),
            Self::Http(event) => info!(target: "rb2_network", "{}", event.to_json("http")),
            Self::Https(event) => info!(target: "rb2_network", "{}", event.to_json("https")),
        }
    }
}

fn base_payload(common: &CommonFields) -> Value {
    json!({
        "timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "direction": common.direction.as_str(),
        "interface": common.interface,
        "src_ip": common.src_ip,
        "src_port": common.src_port,
        "dst_ip": common.dst_ip,
        "dst_port": common.dst_port,
        "transport": common.transport,
        "truncated": common.truncated,
        "host_name": get_hostname(),
        "host_id": get_machine_id(),
    })
}

impl DnsEvent {
    fn to_json(&self, protocol: &str) -> Value {
        let mut payload = base_payload(&self.common);
        let object = payload
            .as_object_mut()
            .expect("base_payload must return a JSON object");
        object.insert("protocol".into(), json!(protocol));
        object.insert("host".into(), json!(self.query_name));
        object.insert("query_type".into(), json!(self.query_type));
        object.insert("query_class".into(), json!(self.query_class));
        payload
    }
}

impl HttpEvent {
    fn to_json(&self, protocol: &str) -> Value {
        let mut payload = base_payload(&self.common);
        let object = payload
            .as_object_mut()
            .expect("base_payload must return a JSON object");
        object.insert("protocol".into(), json!(protocol));
        object.insert("method".into(), json!(self.method));
        object.insert("host".into(), json!(self.host));
        object.insert("path".into(), json!(self.path));
        object.insert("http_version".into(), json!(self.http_version));
        object.insert("request_line".into(), json!(self.request_line));
        payload
    }
}

impl HttpsEvent {
    fn to_json(&self, protocol: &str) -> Value {
        json!({
            "timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "protocol": protocol,
            "direction": Direction::Outbound.as_str(),
            "transport": "tls",
            "truncated": self.truncated,
            "host_name": get_hostname(),
            "host_id": get_machine_id(),
            "pid": self.pid,
            "tid": self.tid,
            "uid": self.uid,
            "comm": self.comm,
            "tls_library": self.tls_library,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "http_version": self.http_version,
            "request_line": self.request_line,
        })
    }
}
