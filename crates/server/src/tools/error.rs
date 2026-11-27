//! Error results shared by core tools and embeddings.

use postkeep_auth::{Refusal, ToolErrorCode};
use postkeep_upstream::http::MAX_RETRY_AFTER_SECS;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock};
use serde::Serialize;

/// A tool error with a message for the caller and a machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ToolError {
    code: ToolErrorCode,
    message: String,
    retry_after_seconds: Option<u64>,
}

#[derive(Serialize)]
struct WireMeta {
    code: ToolErrorCode,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_uncertain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
}

impl ToolError {
    /// Creates a tool error with no suggested retry delay.
    #[must_use]
    pub fn new(code: ToolErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    /// Sets the delay in seconds for a retryable error, clamped to 24 hours.
    #[must_use]
    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after_seconds = self
            .code
            .retryable()
            .then_some(secs.min(MAX_RETRY_AFTER_SECS));
        self
    }

    /// Uses a check's message and code, defaulting to permission denied.
    #[must_use]
    pub fn from_refusal(refusal: &Refusal) -> Self {
        Self::new(
            refusal.code().unwrap_or(ToolErrorCode::PermissionDenied),
            refusal.message(),
        )
        .with_delay(refusal.retry_after_seconds())
    }

    pub(super) fn with_delay(self, seconds: Option<u64>) -> Self {
        match seconds {
            Some(seconds) => self.with_retry_after(seconds),
            None => self,
        }
    }

    /// Changes only the human-readable message.
    #[must_use]
    pub fn map_message(mut self, map: impl FnOnce(String) -> String) -> Self {
        self.message = map(self.message);
        self
    }

    /// The machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> ToolErrorCode {
        self.code
    }

    /// The human-readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The suggested delay in seconds, if present and retryable.
    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// Returns an MCP error result: prose first, then compact JSON metadata.
    #[must_use]
    pub fn into_result(self) -> CallToolResult {
        let meta = WireMeta {
            code: self.code,
            retryable: self.code.retryable(),
            outcome_uncertain: self.code.outcome_uncertain().then_some(true),
            retry_after_seconds: self.retry_after_seconds,
        };
        // The wire type contains only a unit enum, booleans and an integer.
        let json = serde_json::json!(meta).to_string();
        CallToolResult::error(vec![
            ContentBlock::text(self.message),
            ContentBlock::text(json),
        ])
    }
}

impl IntoCallToolResult for ToolError {
    fn into_call_tool_result(self) -> Result<CallToolResponse, rmcp::ErrorData> {
        Ok(self.into_result().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn errors_have_two_text_blocks_and_no_structured_metadata() {
        let result = ToolError::new(ToolErrorCode::RateLimited, "not now")
            .with_retry_after(0)
            .into_result();
        let wire = serde_json::to_value(result).unwrap();
        assert_eq!(wire["isError"], true);
        assert!(wire.get("structuredContent").is_none());
        assert!(wire.get("_meta").is_none());
        assert_eq!(wire["content"].as_array().unwrap().len(), 2);
        assert_eq!(wire["content"][0], json!({"type":"text", "text":"not now"}));
        assert_eq!(wire["content"][1]["type"], "text");
        let text = wire["content"][1]["text"].as_str().unwrap();
        assert!(!text.contains('\n'));
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            json!({
                "code":"rate_limited", "retryable":true, "retry_after_seconds":0
            })
        );
    }

    #[test]
    fn changing_prose_preserves_retry_and_uncertainty() {
        for (code, expected) in [
            (
                ToolErrorCode::Busy,
                json!({"code":"busy","retryable":true,"retry_after_seconds":86400}),
            ),
            (
                ToolErrorCode::SubmissionUncertain,
                json!({"code":"submission_uncertain","retryable":false,"outcome_uncertain":true}),
            ),
            (
                ToolErrorCode::InvalidInput,
                json!({"code":"invalid_input","retryable":false}),
            ),
        ] {
            let result = ToolError::new(code, "message")
                .with_retry_after(u64::MAX)
                .map_message(|message| format!("{message} suffix"))
                .into_result();
            assert_eq!(result.content[0].as_text().unwrap().text, "message suffix");
            let meta: Value =
                serde_json::from_str(&result.content[1].as_text().unwrap().text).unwrap();
            assert_eq!(meta, expected);
        }
    }
}
