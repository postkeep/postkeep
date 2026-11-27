//! Request construction shared by the Streamable HTTP tests.

use axum::body::Body;
use axum::http::{Request, header, request::Builder};
use postkeep::app::MCP_PATH;
use serde_json::{Value, json};

/// Starts an MCP POST before adding authentication or encoding the RPC.
pub fn post(host: &str, protocol: &str) -> Builder {
    Request::post(MCP_PATH)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", protocol)
}

/// Builds an authenticated request with the 2026-07-28 headers and metadata.
pub fn authenticated_2026(
    host: &str,
    token: &str,
    method: &str,
    mut params: Value,
) -> Request<Body> {
    const PROTOCOL: &str = "2026-07-28";
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut request = post(host, PROTOCOL)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("mcp-method", method);
    if method == "resources/read" {
        request = request.header("mcp-name", params["uri"].as_str().unwrap());
    }
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    request.body(Body::from(body.to_string())).unwrap()
}
