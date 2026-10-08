//! Product metadata: reading it, and committing it atomically with an audit row.
//!
//! Product metadata lives in side tables keyed by the existing interface and
//! client identifiers, so the proven network schema is never rewritten. That
//! choice has one consequence this module owns: `write_desired` replaces the
//! `clients` and `peers` tables wholesale, and both product tables cascade from
//! `clients`. Every write path therefore reads the product snapshot and writes
//! it back in the same transaction, so a desired-state commit can never silently
//! delete an operator's client labels.
//!
//! [`StateStore::mutate_product`] is the only path that changes product state.
//! It performs the whole contract in one IMMEDIATE transaction: verify the
//! expected generation, load both snapshots, apply the typed mutation, validate,
//! write desired and product rows, append one bounded audit event, advance the
//! generation, commit. A failure at any step -- including the audit insert --
//! rolls the desired mutation back with it.

use super::{
    desired::{load_desired_for_transaction, write_desired_for_transaction},
    sql::read_generation,
    StateStore,
};
use crate::{
    domain::{DesiredGeneration, DesiredState, InterfaceId, PrincipalId},
    product::model::{
        AdvertisedEndpoint, AuditAction, AuditCursor, AuditEvent, AuditEventId, AuditOutcome,
        AuditResourceKind, ClientEnabled, ClientLabel, ClientProductSettings,
        EnrollmentCapabilityId,
    },
    state::{error::StateError, schema},
};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::{collections::BTreeMap, net::IpAddr};

/// Product settings for one managed interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceProductState {
    pub interface_id: InterfaceId,
    pub advertised_endpoint: AdvertisedEndpoint,
}

/// Product settings for one managed client, plus its ordered DNS list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientProductRecord {
    pub settings: ClientProductSettings,
    pub dns_servers: Vec<IpAddr>,
}

impl ClientProductRecord {
    /// A new enabled record with a derived label and no DNS.
    pub fn new(label: ClientLabel, now: i64) -> Self {
        Self {
            settings: ClientProductSettings {
                label,
                enabled: ClientEnabled::Enabled,
                client_keepalive_seconds: None,
                created_at: now,
                updated_at: now,
            },
            dns_servers: Vec::new(),
        }
    }
}

/// The whole product snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProductState {
    pub interfaces: BTreeMap<InterfaceId, InterfaceProductState>,
    pub clients: BTreeMap<crate::domain::ClientId, ClientProductRecord>,
}

/// The product snapshot paired with the generation that committed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedProductState {
    pub generation: DesiredGeneration,
    pub state: ProductState,
}

/// A committed product mutation together with the audit row it wrote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedProductState {
    pub generation: DesiredGeneration,
    pub state: DesiredState,
    pub product: ProductState,
    pub audit: AuditEvent,
}

/// What a product mutation says to record about itself.
///
/// Bounded categories only. There is deliberately no message field: the audit
/// table has no column that could hold one, so a caller cannot smuggle a request
/// body or an internal error string into the trail even by trying.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductAudit {
    pub action: AuditAction,
    pub resource_kind: AuditResourceKind,
    pub resource_id: Option<String>,
}

impl ProductAudit {
    pub fn client(action: AuditAction, id: impl ToString) -> Self {
        Self {
            action,
            resource_kind: AuditResourceKind::Client,
            resource_id: Some(id.to_string()),
        }
    }

    pub fn server(action: AuditAction, id: impl ToString) -> Self {
        Self {
            action,
            resource_kind: AuditResourceKind::Server,
            resource_id: Some(id.to_string()),
        }
    }
}

impl StateStore {
    /// Reads the product snapshot together with its generation.
    pub fn load_product(&self) -> Result<PersistedProductState, StateError> {
        let connection = self.lock()?;
        Ok(PersistedProductState {
            generation: read_generation(&connection)?,
            state: read_product(&connection)?,
        })
    }

    /// Commits one typed product mutation atomically with its audit row.
    ///
    /// The closure sees the current desired *and* product state and returns the
    /// next desired state plus the audit row to append. Validation of the full
    /// next state, the product writes, the audit insert, and the generation
    /// advance all happen inside one IMMEDIATE transaction, so a rejected
    /// mutation leaves neither rows nor a generation behind -- and an audit row
    /// can never exist without the mutation it describes.
    ///
    /// Post-commit kernel reconciliation is deliberately *not* part of this: the
    /// SQLite transaction cannot contain the kernel's answer, and pretending
    /// otherwise is the ambiguity [`crate::product::ProductMutationReceipt`]
    /// exists to remove.
    pub fn mutate_product(
        &self,
        expected_generation: DesiredGeneration,
        principal_id: Option<PrincipalId>,
        apply: impl FnOnce(
            &DesiredState,
            &mut ProductState,
        ) -> Result<(DesiredState, ProductAudit), StateError>,
    ) -> Result<CommittedProductState, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;

        let current = read_generation(&transaction)?;
        if current != expected_generation {
            return Err(StateError::StaleGeneration {
                expected: expected_generation.to_storage() as u64,
                actual: current.to_storage() as u64,
            });
        }

        let desired = load_desired_for_transaction(&transaction)?;
        let mut product = read_product(&transaction)?;

        let (next_state, audit) = apply(&desired.state, &mut product)?;
        crate::domain::validate_desired_state(&next_state)?;
        validate_product(&next_state, &product)?;

        let next_generation = current.next().ok_or(StateError::GenerationExhausted)?;

        // Desired first: it cascades the product tables away, and the product
        // write immediately repopulates them with the validated snapshot.
        write_desired_for_transaction(&transaction, &next_state)?;
        write_product(&transaction, &product)?;

        let occurred_at = schema::now_seconds();
        let event = insert_audit_event(
            &transaction,
            principal_id,
            audit,
            Some(current),
            Some(next_generation),
            occurred_at,
        )?;

        transaction
            .execute(
                "UPDATE installation SET desired_generation = ?1, updated_at = ?2 WHERE singleton = 1",
                rusqlite::params![next_generation.to_storage(), occurred_at],
            )
            .map_err(StateError::database)?;

        transaction.commit().map_err(StateError::database)?;

        Ok(CommittedProductState {
            generation: next_generation,
            state: next_state,
            product,
            audit: event,
        })
    }

    /// Appends a bounded audit row outside a desired-state mutation.
    ///
    /// Used for outcomes that are genuinely not part of a commit -- most
    /// importantly a post-commit reconciliation failure, which the kernel
    /// decides after the transaction that wrote the mutation has closed.
    /// Carries no generation window, because it describes no generation change.
    pub fn append_audit_event(
        &self,
        principal_id: Option<PrincipalId>,
        audit: ProductAudit,
    ) -> Result<AuditEvent, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let event = insert_audit_event(
            &transaction,
            principal_id,
            audit,
            None,
            None,
            schema::now_seconds(),
        )?;
        transaction.commit().map_err(StateError::database)?;
        Ok(event)
    }

    /// Stores a digest-only enrollment capability and its audit row atomically.
    pub(crate) fn create_enrollment_capability(
        &self,
        capability_id: EnrollmentCapabilityId,
        client_id: crate::domain::ClientId,
        token_digest: &str,
        principal_id: PrincipalId,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        transaction.execute(
            "INSERT INTO enrollment_capabilities (capability_id, client_id, token_digest, creator_principal_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![capability_id.to_string(), client_id.to_string(), token_digest, principal_id.to_string(), created_at, expires_at],
        ).map_err(StateError::database)?;
        insert_audit_event(
            &transaction,
            Some(principal_id),
            ProductAudit {
                action: AuditAction::EnrollmentCapabilityCreated,
                resource_kind: AuditResourceKind::EnrollmentCapability,
                resource_id: Some(capability_id.to_string()),
            },
            None,
            None,
            created_at,
        )?;
        transaction.commit().map_err(StateError::database)
    }

    /// Revokes an unused capability and appends the bounded audit event in the
    /// same write transaction. Expiry and prior consumption are permanent.
    pub(crate) fn revoke_enrollment_capability(
        &self,
        capability_id: EnrollmentCapabilityId,
        principal_id: PrincipalId,
        now: i64,
    ) -> Result<bool, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let changed = transaction.execute(
            "UPDATE enrollment_capabilities SET revoked_at = ?1 WHERE capability_id = ?2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?1",
            rusqlite::params![now, capability_id.to_string()],
        ).map_err(StateError::database)?;
        if changed == 0 {
            return Ok(false);
        }
        insert_audit_event(
            &transaction,
            Some(principal_id),
            ProductAudit {
                action: AuditAction::EnrollmentCapabilityRevoked,
                resource_kind: AuditResourceKind::EnrollmentCapability,
                resource_id: Some(capability_id.to_string()),
            },
            None,
            None,
            now,
        )?;
        transaction.commit().map_err(StateError::database)?;
        Ok(true)
    }

    /// Atomically validates, consumes, audits, and loads the one client
    /// artifact. A failed token or unavailable capability changes no row.
    pub(crate) fn consume_enrollment_capability(
        &self,
        capability_id: EnrollmentCapabilityId,
        token_digest: &str,
        now: i64,
    ) -> Result<Option<crate::product::SecretArtifact>, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let eligible: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM enrollment_capabilities WHERE capability_id = ?1 AND token_digest = ?2 AND expires_at > ?3 AND consumed_at IS NULL AND revoked_at IS NULL)",
            rusqlite::params![capability_id.to_string(), token_digest, now], |row| row.get(0),
        ).map_err(StateError::database)?;
        if !eligible {
            return Ok(None);
        }
        let desired = load_desired_for_transaction(&transaction)?;
        let product = read_product(&transaction)?;
        let capability =
            crate::product::service::material_from_snapshots(&desired.state, &product, {
                let client: String = transaction
                    .query_row(
                        "SELECT client_id FROM enrollment_capabilities WHERE capability_id = ?1",
                        [capability_id.to_string()],
                        |row| row.get(0),
                    )
                    .map_err(StateError::database)?;
                client.parse().map_err(|_| {
                    StateError::Corrupt("enrollment capability has an invalid client id")
                })?
            });
        let Ok(material) = capability else {
            return Ok(None);
        };
        let Ok(config) = crate::product::render_config(&material) else {
            return Ok(None);
        };
        let changed = transaction.execute(
            "UPDATE enrollment_capabilities SET consumed_at = ?1 WHERE capability_id = ?2 AND token_digest = ?3 AND expires_at > ?1 AND consumed_at IS NULL AND revoked_at IS NULL",
            rusqlite::params![now, capability_id.to_string(), token_digest],
        ).map_err(StateError::database)?;
        if changed != 1 {
            return Ok(None);
        }
        insert_audit_event(
            &transaction,
            None,
            ProductAudit {
                action: AuditAction::EnrollmentCapabilityConsumed,
                resource_kind: AuditResourceKind::EnrollmentCapability,
                resource_id: Some(capability_id.to_string()),
            },
            None,
            None,
            now,
        )?;
        transaction.commit().map_err(StateError::database)?;
        Ok(Some(config))
    }

    /// Reads audit rows newest-first, bounded to `limit`.
    ///
    /// Rows are decoded in two steps -- SQLite text first, domain types second --
    /// so an unrecognised stored category becomes [`StateError::Corrupt`] at one
    /// boundary instead of masquerading as a column-type problem.
    ///
    /// Ordering is `occurred_at` then insertion order, not the random event id:
    /// several mutations can land inside one clock second, and a random tiebreak
    /// would make the trail's order differ between runs.
    pub fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, StateError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT event_id, occurred_at, principal_id, action, resource_kind,
                        resource_id, generation_before, generation_after, outcome
                 FROM audit_events ORDER BY occurred_at DESC, rowid DESC LIMIT ?1",
            )
            .map_err(StateError::database)?;
        let raw = statement
            .query_map([limit.min(1_000) as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(StateError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)?;

        raw.into_iter().map(decode_audit_row).collect()
    }

    /// Reads a newest-first audit page strictly older than the supplied stable
    /// timestamp/event cursor. Audit rows are immutable, so concurrent inserts
    /// cannot reorder an already-issued cursor.
    pub fn audit_events_page(
        &self,
        limit: usize,
        before: Option<AuditCursor>,
    ) -> Result<Vec<AuditEvent>, StateError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT event_id, occurred_at, principal_id, action, resource_kind,
                    resource_id, generation_before, generation_after, outcome
             FROM audit_events
             WHERE (?1 IS NULL OR occurred_at < ?1 OR (occurred_at = ?1 AND rowid <
                    (SELECT rowid FROM audit_events WHERE event_id = ?2 AND occurred_at = ?1)))
             ORDER BY occurred_at DESC, rowid DESC LIMIT ?3",
            )
            .map_err(StateError::database)?;
        let cursor_time = before.map(|cursor| cursor.occurred_at);
        let cursor_id = before.map(|cursor| cursor.event_id.to_string());
        let raw = statement
            .query_map(
                rusqlite::params![cursor_time, cursor_id, limit.min(1_001) as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .map_err(StateError::database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)?;
        raw.into_iter().map(decode_audit_row).collect()
    }
}

type RawAuditRow = (
    String,
    i64,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    String,
);

fn decode_audit_row(
    (
        event_id,
        occurred_at,
        principal_id,
        action,
        resource_kind,
        resource_id,
        generation_before,
        generation_after,
        outcome,
    ): RawAuditRow,
) -> Result<AuditEvent, StateError> {
    Ok(AuditEvent {
        event_id: event_id
            .parse()
            .map_err(|_| StateError::Corrupt("invalid stored audit event id"))?,
        occurred_at,
        principal_id: principal_id
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| StateError::Corrupt("invalid stored audit principal id"))?,
        action: parse_action(&action).ok_or(StateError::Corrupt("unknown stored audit action"))?,
        resource_kind: parse_resource_kind(&resource_kind)
            .ok_or(StateError::Corrupt("unknown stored audit resource kind"))?,
        resource_id,
        // A stored generation that is absent or out of range means the row cannot
        // be interpreted; silently dropping it would hide a corrupted trail.
        generation_before: match generation_before {
            None => None,
            Some(value) => Some(
                DesiredGeneration::from_storage(value)
                    .ok_or(StateError::Corrupt("invalid stored audit generation"))?,
            ),
        },
        generation_after: match generation_after {
            None => None,
            Some(value) => Some(
                DesiredGeneration::from_storage(value)
                    .ok_or(StateError::Corrupt("invalid stored audit generation"))?,
            ),
        },
        outcome: parse_outcome(&outcome)
            .ok_or(StateError::Corrupt("unknown stored audit outcome"))?,
    })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Checks the product snapshot against the desired state it describes.
///
/// A product row that references a client the desired state does not contain is
/// corruption, not a tolerated state: it would mean an address reservation
/// exists for a peer that does not, which is exactly the invariant address
/// allocation depends on.
pub fn validate_product(state: &DesiredState, product: &ProductState) -> Result<(), StateError> {
    let interface_ids: Vec<&InterfaceId> = state.interfaces.iter().map(|i| &i.id).collect();
    for interface_id in product.interfaces.keys() {
        if !interface_ids.contains(&interface_id) {
            return Err(StateError::Corrupt(
                "product settings reference an unknown interface",
            ));
        }
    }

    let client_ids: Vec<&crate::domain::ClientId> = state
        .interfaces
        .iter()
        .flat_map(|i| i.clients.iter())
        .map(|c| &c.id)
        .collect();
    for (client_id, record) in &product.clients {
        if !client_ids.contains(&client_id) {
            return Err(StateError::Corrupt(
                "product settings reference an unknown client",
            ));
        }
        for dns in &record.dns_servers {
            if dns.is_unspecified() || dns.is_multicast() {
                return Err(StateError::Corrupt(
                    "client DNS list contains an unusable address",
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

pub(crate) fn read_product(connection: &Connection) -> Result<ProductState, StateError> {
    let mut interfaces = BTreeMap::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT interface_id, advertised_host, advertised_port
                 FROM interface_product_settings ORDER BY interface_id",
            )
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(StateError::database)?;
        for value in rows {
            let (interface_id, host, port) = value.map_err(StateError::database)?;
            let id: InterfaceId = interface_id
                .parse()
                .map_err(|_| StateError::Corrupt("invalid product interface id"))?;
            let port = u16::try_from(port).map_err(|_| StateError::Corrupt("invalid port"))?;
            interfaces.insert(
                id,
                InterfaceProductState {
                    interface_id: id,
                    advertised_endpoint: AdvertisedEndpoint::new(host, port)
                        .map_err(|_| StateError::Corrupt("invalid advertised endpoint"))?,
                },
            );
        }
    }

    let mut clients = BTreeMap::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT client_id, label, enabled, client_keepalive_seconds,
                        created_at, updated_at
                 FROM client_product_settings ORDER BY client_id",
            )
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(StateError::database)?;
        for value in rows {
            let (client_id, label, enabled, keepalive, created_at, updated_at) =
                value.map_err(StateError::database)?;
            let id: crate::domain::ClientId = client_id
                .parse()
                .map_err(|_| StateError::Corrupt("invalid product client id"))?;
            let keepalive = keepalive
                .map(|seconds| {
                    u16::try_from(seconds)
                        .map_err(|_| StateError::Corrupt("invalid client keepalive"))
                })
                .transpose()?;
            clients.insert(
                id,
                ClientProductRecord {
                    settings: ClientProductSettings {
                        label: ClientLabel::new(label)
                            .map_err(|_| StateError::Corrupt("invalid client label"))?,
                        enabled: if enabled == 1 {
                            ClientEnabled::Enabled
                        } else {
                            ClientEnabled::Disabled
                        },
                        client_keepalive_seconds: keepalive,
                        created_at,
                        updated_at,
                    },
                    dns_servers: read_dns_servers(connection, &client_id)?,
                },
            );
        }
    }

    Ok(ProductState {
        interfaces,
        clients,
    })
}

fn read_dns_servers(connection: &Connection, client_id: &str) -> Result<Vec<IpAddr>, StateError> {
    let mut statement = connection
        .prepare(
            "SELECT address FROM client_dns_servers
             WHERE client_id = ?1 ORDER BY position",
        )
        .map_err(StateError::database)?;
    let rows = statement
        .query_map([client_id], |row| row.get::<_, String>(0))
        .map_err(StateError::database)?;
    let values = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(StateError::database)?;
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| StateError::Corrupt("invalid client DNS address"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

pub(super) fn write_product(
    transaction: &Transaction<'_>,
    product: &ProductState,
) -> Result<(), StateError> {
    // Rewritten wholesale for the same reason `write_desired` rewrites the
    // snapshot: the stored state must not retain a row the product state no
    // longer contains.
    for table in ["client_dns_servers", "client_product_settings"] {
        transaction
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(StateError::database)?;
    }
    transaction
        .execute("DELETE FROM interface_product_settings", [])
        .map_err(StateError::database)?;

    for settings in product.interfaces.values() {
        transaction
            .execute(
                "INSERT INTO interface_product_settings
                     (interface_id, advertised_host, advertised_port)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    settings.interface_id.to_string(),
                    settings.advertised_endpoint.host(),
                    i64::from(settings.advertised_endpoint.port()),
                ],
            )
            .map_err(StateError::database)?;
    }

    for (client_id, record) in &product.clients {
        let client_id = client_id.to_string();
        transaction
            .execute(
                "INSERT INTO client_product_settings
                     (client_id, label, enabled, client_keepalive_seconds,
                      created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    client_id,
                    record.settings.label.as_str(),
                    i64::from(record.settings.enabled.is_enabled()),
                    record.settings.client_keepalive_seconds.map(i64::from),
                    record.settings.created_at,
                    record.settings.updated_at,
                ],
            )
            .map_err(StateError::database)?;
        for (position, dns) in record.dns_servers.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO client_dns_servers (client_id, position, address)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![client_id, position as i64, dns.to_string()],
                )
                .map_err(StateError::database)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_audit_event(
    transaction: &Transaction<'_>,
    principal_id: Option<PrincipalId>,
    audit: ProductAudit,
    generation_before: Option<DesiredGeneration>,
    generation_after: Option<DesiredGeneration>,
    occurred_at: i64,
) -> Result<AuditEvent, StateError> {
    let event_id = AuditEventId::new();
    let outcome = AuditOutcome::Committed;
    transaction
        .execute(
            "INSERT INTO audit_events
                 (event_id, occurred_at, principal_id, action, resource_kind,
                  resource_id, generation_before, generation_after, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                event_id.to_string(),
                occurred_at,
                principal_id.map(|id| id.to_string()),
                audit.action.as_str(),
                audit.resource_kind.as_str(),
                audit.resource_id,
                generation_before.map(DesiredGeneration::to_storage),
                generation_after.map(DesiredGeneration::to_storage),
                outcome.as_str(),
            ],
        )
        .map_err(StateError::database)?;

    Ok(AuditEvent {
        event_id,
        occurred_at,
        principal_id,
        action: audit.action,
        resource_kind: audit.resource_kind,
        resource_id: audit.resource_id,
        generation_before,
        generation_after,
        outcome,
    })
}

fn parse_action(value: &str) -> Option<AuditAction> {
    [
        AuditAction::ServerSetup,
        AuditAction::ClientCreate,
        AuditAction::ClientUpdate,
        AuditAction::ClientEnable,
        AuditAction::ClientDisable,
        AuditAction::ClientDelete,
        AuditAction::EnforcementDegraded,
        AuditAction::EnrollmentCapabilityCreated,
        AuditAction::EnrollmentCapabilityRevoked,
        AuditAction::EnrollmentCapabilityConsumed,
    ]
    .into_iter()
    .find(|action| action.as_str() == value)
}

fn parse_resource_kind(value: &str) -> Option<AuditResourceKind> {
    [
        AuditResourceKind::Server,
        AuditResourceKind::Client,
        AuditResourceKind::EnrollmentCapability,
    ]
    .into_iter()
    .find(|kind| kind.as_str() == value)
}

fn parse_outcome(value: &str) -> Option<AuditOutcome> {
    [
        AuditOutcome::Committed,
        AuditOutcome::Rejected,
        AuditOutcome::Conflicted,
    ]
    .into_iter()
    .find(|outcome| outcome.as_str() == value)
}
