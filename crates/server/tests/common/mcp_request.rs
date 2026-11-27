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

/// Checks and decodes the machine-readable block of a core tool error.
pub fn error_meta(result: &Value) -> Value {
    assert_eq!(result["isError"], true, "{result}");
    assert!(result.get("structuredContent").is_none(), "{result}");
    assert!(result.get("_meta").is_none(), "{result}");
    let blocks = result["content"].as_array().unwrap();
    assert_eq!(blocks.len(), 2, "{result}");
    assert!(blocks.iter().all(|block| block["type"] == "text"));
    let text = blocks[1]["text"].as_str().unwrap();
    assert!(!text.contains('\n'), "{text}");
    serde_json::from_str(text).unwrap()
}
