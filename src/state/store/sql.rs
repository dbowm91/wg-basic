//! Row decoding shared by the desired-snapshot and convergence modules.
//!
//! Every SQLite column value that becomes a domain type is converted here, so
//! a stored representation is changed in exactly one place and an unparseable
//! stored value becomes [`StateError::Corrupt`] at a single boundary instead of
//! being reinterpreted per query.
//!
//! Nothing in this module issues SQL and nothing in it is part of the store's
//! public API: it is an implementation detail of the store façade.

use super::super::{error::StateError, model::InstallationMetadata};
use crate::domain::{
    DesiredGeneration, InstallationId, LinkLifecycle, NetworkPrefix, OwnershipDeclaration,
    ResourcePresence,
};
use ipnet::IpNet;
use rusqlite::{Connection, OptionalExtension};
use std::net::{IpAddr, SocketAddr};

// ---------------------------------------------------------------------------
// Row reading. Row structs intentionally have no `Debug` derive so that a
// future field addition cannot silently expose secret material through logging.
// ---------------------------------------------------------------------------

/// One raw `managed_interfaces` row, before its columns are interpreted.
pub(super) struct InterfaceRow {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) ownership: String,
    pub(super) lifecycle: String,
    pub(super) admin_up: Option<i64>,
    pub(super) private_key: String,
    pub(super) listen_port: Option<i64>,
    pub(super) manage_all_peers: i64,
}

pub(super) fn read_interface_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InterfaceRow> {
    Ok(InterfaceRow {
        id: row.get(0)?,
        name: row.get(1)?,
        ownership: row.get(2)?,
        lifecycle: row.get(3)?,
        admin_up: row.get(4)?,
        private_key: row.get(5)?,
        listen_port: row.get(6)?,
        manage_all_peers: row.get(7)?,
    })
}

/// Reads the singleton installation row, including the current generation.
pub(crate) fn read_installation(
    connection: &Connection,
) -> Result<InstallationMetadata, StateError> {
    let row = connection
        .query_row(
            "SELECT installation_id, desired_generation, created_at, updated_at
             FROM installation WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(StateError::database)?
        .ok_or(StateError::Corrupt("installation row missing"))?;

    let installation_id: InstallationId = row
        .0
        .parse()
        .map_err(|_| StateError::Corrupt("invalid installation id"))?;
    let generation =
        DesiredGeneration::from_storage(row.1).ok_or(StateError::Corrupt("invalid generation"))?;
    Ok(InstallationMetadata {
        installation_id,
        desired_generation: generation,
        created_at: row.2,
        updated_at: row.3,
    })
}

/// Reads only the current desired generation.
pub(super) fn read_generation(connection: &Connection) -> Result<DesiredGeneration, StateError> {
    let raw: i64 = connection
        .query_row(
            "SELECT desired_generation FROM installation WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(StateError::database)?
        .ok_or(StateError::Corrupt("installation row missing"))?;
    DesiredGeneration::from_storage(raw).ok_or(StateError::Corrupt("invalid generation"))
}

/// Decodes a nullable generation column, treating a stored invalid value as
/// corruption rather than as "unset".
pub(super) fn read_optional_generation(
    raw: Option<i64>,
    column: &'static str,
) -> Result<Option<DesiredGeneration>, StateError> {
    match raw {
        None => Ok(None),
        Some(value) => DesiredGeneration::from_storage(value)
            .map(Some)
            .ok_or(StateError::Corrupt(match column {
                "attempted" => "invalid attempted generation",
                _ => "invalid converged generation",
            })),
    }
}

// ---------------------------------------------------------------------------
// Column decoding
// ---------------------------------------------------------------------------

pub(super) fn parse_prefix(value: &str) -> Result<NetworkPrefix, StateError> {
    value
        .parse()
        .map_err(|_| StateError::Corrupt("stored prefix is not a valid network prefix"))
}

pub(super) fn parse_ipnet(value: &str) -> Result<IpNet, StateError> {
    value
        .parse()
        .map_err(|_| StateError::Corrupt("stored address is not a valid prefix"))
}

pub(super) fn parse_ipaddr(value: &str) -> Result<IpAddr, StateError> {
    value
        .parse()
        .map_err(|_| StateError::Corrupt("stored gateway is not a valid address"))
}

pub(super) fn parse_socket_addr(value: &str) -> Result<SocketAddr, StateError> {
    value
        .parse()
        .map_err(|_| StateError::Corrupt("stored endpoint is not a valid socket address"))
}

pub(super) fn parse_ownership(value: &str) -> Result<OwnershipDeclaration, StateError> {
    match value {
        "managed" => Ok(OwnershipDeclaration::Managed),
        "observe_only" => Ok(OwnershipDeclaration::ObserveOnly),
        _ => Err(StateError::Corrupt("unknown ownership declaration")),
    }
}

pub(super) fn parse_lifecycle(value: &str) -> Result<LinkLifecycle, StateError> {
    match value {
        "present" => Ok(LinkLifecycle::Present),
        "absent" => Ok(LinkLifecycle::Absent),
        _ => Err(StateError::Corrupt("unknown link lifecycle")),
    }
}

pub(super) fn parse_presence(value: &str) -> Result<ResourcePresence, StateError> {
    match value {
        "present" => Ok(ResourcePresence::Present),
        "absent" => Ok(ResourcePresence::Absent),
        _ => Err(StateError::Corrupt("unknown resource presence")),
    }
}

/// Parses an ordered prefix column that carries no foreign key.
pub(super) fn parse_prefix_column(values: Vec<String>) -> Result<Vec<NetworkPrefix>, StateError> {
    values.iter().map(|value| parse_prefix(value)).collect()
}

/// Renders prefixes in their canonical stored form.
pub(super) fn prefix_strings(prefixes: &[NetworkPrefix]) -> Vec<String> {
    prefixes.iter().map(|prefix| prefix.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Column encoding
// ---------------------------------------------------------------------------

pub(super) fn ownership_label(value: OwnershipDeclaration) -> &'static str {
    match value {
        OwnershipDeclaration::Managed => "managed",
        OwnershipDeclaration::ObserveOnly => "observe_only",
    }
}

pub(super) fn lifecycle_label(value: LinkLifecycle) -> &'static str {
    match value {
        LinkLifecycle::Present => "present",
        LinkLifecycle::Absent => "absent",
    }
}

pub(super) fn presence_label(value: ResourcePresence) -> &'static str {
    match value {
        ResourcePresence::Present => "present",
        ResourcePresence::Absent => "absent",
    }
}
