use crate::{
    domain::InterfaceName,
    wireguard::{ObservedWireGuardDevice, WireGuardApplyReceipt, WireGuardDevicePatch},
};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub protocol_version: u16,
    pub request_id: u64,
    pub operation: RequestOperation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RequestOperation {
    Ping,
    InspectCapabilities,
    ObserveWireGuardDevice {
        interface: InterfaceName,
    },
    ApplyWireGuardDevice {
        interface: InterfaceName,
        patch: WireGuardDevicePatch,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub protocol_version: u16,
    pub request_id: u64,
    pub result: Result<ResponseBody, ProtocolError>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
pub enum ResponseBody {
    Pong { service: String, version: String },
    Capabilities(super::NetworkCapabilitySnapshot),
    WireGuardDevice(ObservedWireGuardDevice),
    WireGuardApplied(WireGuardApplyReceipt),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolError {
    UnsupportedVersion,
    Unauthorized,
    MalformedRequest,
    InternalFailure,
    InvalidInput,
    NotFound,
    Conflict,
    PermissionDenied,
    UnsupportedBackend,
    KernelRejected,
    BackendFailure,
}

impl ResponseEnvelope {
    pub(crate) fn failure(request_id: u64, error: ProtocolError) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_round_trip_with_stable_operation_names() {
        let request = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: 42,
            operation: RequestOperation::InspectCapabilities,
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(std::str::from_utf8(&encoded)
            .unwrap()
            .contains("inspect_capabilities"));
        let decoded: RequestEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, request.protocol_version);
        assert_eq!(decoded.request_id, request.request_id);
        assert!(matches!(
            decoded.operation,
            RequestOperation::InspectCapabilities
        ));

        let response = ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: 42,
            result: Ok(ResponseBody::Pong {
                service: "wg-basic-netd".into(),
                version: "0.1.0".into(),
            }),
        };
        let decoded: ResponseEnvelope =
            serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn unknown_operations_and_fields_are_rejected_without_echoing_payload() {
        let error = serde_json::from_str::<RequestEnvelope>(r#"{"protocol_version":1,"request_id":1,"operation":"exec","parameters":{"command":"secret"}}"#).unwrap_err();
        assert!(!error.to_string().contains("secret"));
        assert!(serde_json::from_str::<RequestEnvelope>(
            r#"{"protocol_version":1,"request_id":1,"operation":"ping","unexpected":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<RequestEnvelope>(
            r#"{"protocol_version":1,"request_id":1,"operation":"ping","parameters":{"unexpected":true}}"#
        )
        .is_err());
        for operation in [
            "exec",
            "shell",
            "write_file",
            "set_sysctl",
            "apply_nft",
            "send_netlink",
        ] {
            let request =
                format!(r#"{{"protocol_version":1,"request_id":2,"operation":"{operation}"}}"#);
            assert!(
                serde_json::from_str::<RequestEnvelope>(&request).is_err(),
                "{operation} must remain outside the protocol"
            );
        }
    }

    #[test]
    fn wireguard_patch_round_trip_keeps_secret_debug_redacted() {
        let private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
        let request = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: 8,
            operation: RequestOperation::ApplyWireGuardDevice {
                interface: "wg0".parse().unwrap(),
                patch: WireGuardDevicePatch {
                    private_key: crate::wireguard::FieldUpdate::Set(
                        crate::domain::PrivateKey::new(private_key.clone()).unwrap(),
                    ),
                    listen_port: crate::wireguard::FieldUpdate::Keep,
                    peer: None,
                },
            },
        };
        assert!(!format!("{request:?}").contains(&private_key));
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: RequestEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(
            decoded.operation,
            RequestOperation::ApplyWireGuardDevice { .. }
        ));
        assert!(!format!("{decoded:?}").contains(&private_key));
    }
}
