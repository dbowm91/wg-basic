//! The desired snapshot: reading it and committing a new one.
//!
//! A commit is one atomic generation advance. `StateStore::mutate` re-reads the
//! stored snapshot inside the same write transaction that advances the
//! generation, so a stale writer, a validation failure, or any write failure
//! leaves no partial row changes and does not advance the generation.

use super::{
    sql::{
        lifecycle_label, ownership_label, parse_ipaddr, parse_ipnet, parse_lifecycle,
        parse_ownership, parse_prefix, parse_prefix_column, parse_presence, parse_socket_addr,
        prefix_strings, presence_label, read_generation, read_installation, read_interface_row,
        InterfaceRow,
    },
    StateStore,
};
use crate::{
    domain::{
        validate_desired_state, ClientRoutePolicy, DesiredAddress, DesiredClient,
        DesiredGeneration, DesiredInterface, DesiredNetworkPolicy, DesiredPeer, DesiredState,
        InterfaceId, InterfaceName, ManagedRoute, NetworkPrefix, PresharedKey, PrivateKey,
        PublicKey,
    },
    state::{
        error::StateError,
        model::{CommittedDesiredState, InstallationMetadata, PersistedDesiredState},
        schema,
    },
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

impl StateStore {
    /// Reads installation metadata, including the current desired generation.
    pub fn installation_metadata(&self) -> Result<InstallationMetadata, StateError> {
        let connection = self.lock()?;
        read_installation(&connection)
    }

    /// Reads the current desired generation.
    pub fn current_generation(&self) -> Result<DesiredGeneration, StateError> {
        Ok(self.installation_metadata()?.desired_generation)
    }

    /// Loads the full desired snapshot together with its generation.
    pub fn load(&self) -> Result<PersistedDesiredState, StateError> {
        let connection = self.lock()?;
        load_desired(&connection)
    }

    /// Commits a new desired snapshot if `expected_generation` is still current.
    ///
    /// The full snapshot is validated inside the same write transaction that
    /// advances the generation. A stale writer, a validation failure, or any
    /// write failure performs no row changes and does not advance the
    /// generation.
    pub fn mutate(
        &self,
        expected_generation: DesiredGeneration,
        update: impl FnOnce(&DesiredState) -> Result<DesiredState, StateError>,
    ) -> Result<CommittedDesiredState, StateError> {
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

        let state = load_desired_for_transaction(&transaction)?;
        let next_state = update(&state.state)?;
        validate_desired_state(&next_state)?;

        let next_generation = current.next().ok_or(StateError::GenerationExhausted)?;

        // Product rows are read before the desired rewrite and written back
        // after it, because rewriting `clients`/`peers` cascades them away. A
        // plain non-product commit must not be able to erase an operator's
        // labels, enable bits, or DNS lists.
        let product = super::product::read_product(&transaction)?;

        write_desired_for_transaction(&transaction, &next_state)?;
        super::product::write_product(&transaction, &product)?;
        transaction
            .execute(
                "UPDATE installation SET desired_generation = ?1, updated_at = ?2 WHERE singleton = 1",
                rusqlite::params![next_generation.to_storage(), schema::now_seconds()],
            )
            .map_err(StateError::database)?;

        transaction.commit().map_err(StateError::database)?;

        Ok(CommittedDesiredState {
            generation: next_generation,
            state: next_state,
        })
    }
}

/// Reads the desired snapshot from inside an open write transaction.
///
/// Shared with the product writer so both read the same rows, at the same
/// generation, under the same lock.
pub(super) fn load_desired_for_transaction(
    transaction: &Transaction<'_>,
) -> Result<PersistedDesiredState, StateError> {
    let generation = read_generation(transaction)?;
    let state = read_desired(transaction)?;
    Ok(PersistedDesiredState { generation, state })
}

/// Rewrites the desired snapshot inside an open write transaction.
///
/// Note for callers: this deletes and reinserts `clients` and `peers`, which
/// cascades into `client_product_settings` and `client_dns_servers`. Every
/// write path must therefore rewrite the product rows afterwards in the same
/// transaction, or a purely non-product commit would silently erase an
/// operator's labels and DNS lists.
pub(super) fn write_desired_for_transaction(
    transaction: &Transaction<'_>,
    state: &DesiredState,
) -> Result<(), StateError> {
    write_desired(transaction, state)
}

pub(crate) fn load_desired(connection: &Connection) -> Result<PersistedDesiredState, StateError> {
    let generation = read_generation(connection)?;
    let state = read_desired(connection)?;
    Ok(PersistedDesiredState { generation, state })
}

fn read_desired(connection: &Connection) -> Result<DesiredState, StateError> {
    let mut interfaces = Vec::new();
    let interface_rows = {
        let mut statement = connection
            .prepare(
                "SELECT id, name, ownership, lifecycle, admin_up, private_key, listen_port,
                        manage_all_peers
                 FROM managed_interfaces ORDER BY position, id",
            )
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([], read_interface_row)
            .map_err(StateError::database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)?
    };

    for row in interface_rows {
        interfaces.push(assemble_interface(connection, row)?);
    }

    let client_routes = ClientRoutePolicy {
        prefixes: parse_prefix_column(query_prefixes(
            connection,
            "SELECT prefix FROM client_global_route_prefixes ORDER BY position",
        )?)?,
    };

    let network_policy = read_network_policy(connection, &interfaces)?;

    Ok(DesiredState {
        interfaces,
        client_routes,
        network_policy,
    })
}

fn assemble_interface(
    connection: &Connection,
    row: InterfaceRow,
) -> Result<DesiredInterface, StateError> {
    let id: InterfaceId = row
        .id
        .parse()
        .map_err(|_| StateError::Corrupt("invalid interface id"))?;
    let name: InterfaceName = row
        .name
        .parse()
        .map_err(|_| StateError::Corrupt("invalid interface name"))?;
    let ownership = parse_ownership(&row.ownership)?;
    let lifecycle = parse_lifecycle(&row.lifecycle)?;

    let tunnel_prefixes = query_prefixes_for(
        connection,
        "SELECT prefix FROM interface_tunnel_prefixes WHERE interface_id = ?1 ORDER BY position",
        &row.id,
    )?;

    let mut addresses = Vec::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT address, presence FROM interface_addresses
                 WHERE interface_id = ?1 ORDER BY position",
            )
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([&row.id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(StateError::database)?;
        for value in rows {
            let (address, presence) = value.map_err(StateError::database)?;
            addresses.push(DesiredAddress {
                address: parse_ipnet(&address)?,
                presence: parse_presence(&presence)?,
            });
        }
    }

    let mut routes = Vec::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT destination, gateway, presence FROM managed_routes
                 WHERE interface_id = ?1 ORDER BY position",
            )
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([&row.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(StateError::database)?;
        for value in rows {
            let (destination, gateway, presence) = value.map_err(StateError::database)?;
            routes.push(ManagedRoute {
                destination: parse_prefix(&destination)?,
                gateway: gateway.as_deref().map(parse_ipaddr).transpose()?,
                presence: parse_presence(&presence)?,
            });
        }
    }

    let mut peers = Vec::new();
    let peer_ids: Vec<String> = {
        let mut statement = connection
            .prepare("SELECT id FROM peers WHERE interface_id = ?1 ORDER BY position, id")
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([&row.id], |r| r.get::<_, String>(0))
            .map_err(StateError::database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)?
    };
    for peer_id in peer_ids {
        peers.push(assemble_peer(connection, &peer_id)?);
    }

    let mut clients = Vec::new();
    {
        // Read-only compatibility paths intentionally inspect historical
        // databases before migration (for example updater restore checks).
        // Schema versions before v6 have no assigned_ipv6_address column.
        let schema_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(StateError::database)?;
        let query = if schema_version >= 6 {
            "SELECT id, peer_id, assigned_address, assigned_ipv6_address FROM clients
             WHERE interface_id = ?1 ORDER BY position, id"
        } else {
            "SELECT id, peer_id, assigned_address, NULL FROM clients
             WHERE interface_id = ?1 ORDER BY position, id"
        };
        let mut statement = connection.prepare(query).map_err(StateError::database)?;
        let rows = statement
            .query_map([&row.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(StateError::database)?;
        let collected: Vec<(String, String, String, Option<String>)> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)?;
        for (id, peer_id, assigned, assigned_ipv6) in collected {
            clients.push(DesiredClient {
                id: id.parse().map_err(|_| StateError::Corrupt("invalid client id"))?,
                peer_id: peer_id
                    .parse()
                    .map_err(|_| StateError::Corrupt("invalid client peer id"))?,
                assigned_address: parse_ipnet(&assigned)?,
                assigned_ipv6_address: assigned_ipv6
                    .as_deref()
                    .map(parse_ipnet)
                    .transpose()?,
                route_policy: ClientRoutePolicy {
                    prefixes: query_prefixes_for(
                        connection,
                        "SELECT prefix FROM client_route_prefixes WHERE client_id = ?1 ORDER BY position",
                        &id,
                    )?,
                },
            });
        }
    }

    Ok(DesiredInterface {
        id,
        name,
        ownership,
        lifecycle,
        admin_up: row.admin_up.map(|value| value == 1),
        private_key: PrivateKey::new(row.private_key)
            .map_err(|_| StateError::Corrupt("invalid private key"))?,
        listen_port: row.listen_port.map(|value| value as u16),
        manage_all_peers: row.manage_all_peers == 1,
        tunnel_prefixes,
        addresses,
        routes,
        peers,
        clients,
    })
}

fn assemble_peer(connection: &Connection, peer_id: &str) -> Result<DesiredPeer, StateError> {
    let row = connection
        .query_row(
            "SELECT id, public_key, private_key, preshared_key,
                    persistent_keepalive_seconds, endpoint
             FROM peers WHERE id = ?1",
            [peer_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .map_err(StateError::database)?;

    let allowed_ips = query_prefixes_for(
        connection,
        "SELECT prefix FROM peer_allowed_ips WHERE peer_id = ?1 ORDER BY position",
        peer_id,
    )?;

    Ok(DesiredPeer {
        id: row
            .0
            .parse()
            .map_err(|_| StateError::Corrupt("invalid peer id"))?,
        public_key: PublicKey::new(row.1)
            .map_err(|_| StateError::Corrupt("invalid peer public key"))?,
        private_key: row
            .2
            .map(PrivateKey::new)
            .transpose()
            .map_err(|_| StateError::Corrupt("invalid peer private key"))?,
        preshared_key: row
            .3
            .map(PresharedKey::new)
            .transpose()
            .map_err(|_| StateError::Corrupt("invalid peer preshared key"))?,
        allowed_ips,
        persistent_keepalive_seconds: row.4.map(|value| value as u16),
        endpoint: row.5.as_deref().map(parse_socket_addr).transpose()?,
    })
}

fn read_network_policy(
    connection: &Connection,
    interfaces: &[DesiredInterface],
) -> Result<Option<DesiredNetworkPolicy>, StateError> {
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)?;
    let ipv6_column = if schema_version >= 7 {
        "ipv6_forwarding_required"
    } else {
        "0"
    };
    let query = format!(
        "SELECT wireguard_interface, ipv4_forwarding_required, egress_interface, masquerade, {ipv6_column}
         FROM network_policy WHERE singleton = 1"
    );
    let row = connection
        .query_row(&query, [], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .optional()
        .map_err(StateError::database)?;

    let Some((interface, forwarding_required, egress, masquerade, ipv6_forwarding_required)) = row
    else {
        return Ok(None);
    };
    let wireguard_interface: InterfaceName = interface
        .parse()
        .map_err(|_| StateError::Corrupt("invalid policy interface"))?;
    if !interfaces.iter().any(|i| i.name == wireguard_interface) {
        return Err(StateError::Corrupt(
            "policy references an unmanaged interface",
        ));
    }
    Ok(Some(DesiredNetworkPolicy {
        wireguard_interface,
        ipv4_forwarding_required: forwarding_required == 1,
        ipv6_forwarding_required: ipv6_forwarding_required == 1,
        egress_interface: egress
            .parse()
            .map_err(|_| StateError::Corrupt("invalid policy egress"))?,
        source_prefixes: parse_prefix_column(query_prefixes(
            connection,
            "SELECT prefix FROM network_policy_source_prefixes ORDER BY position",
        )?)?,
        masquerade: masquerade == 1,
    }))
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

fn write_desired(transaction: &Transaction<'_>, state: &DesiredState) -> Result<(), StateError> {
    // The snapshot is replaced wholesale: child rows are removed and rewritten so
    // the stored state cannot retain a row the desired state no longer contains.
    for table in [
        "interface_tunnel_prefixes",
        "interface_addresses",
        "managed_routes",
        "peer_allowed_ips",
        "client_route_prefixes",
        "clients",
        "peers",
        "managed_interfaces",
    ] {
        transaction
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(StateError::database)?;
    }
    transaction
        .execute("DELETE FROM network_policy_source_prefixes", [])
        .map_err(StateError::database)?;
    transaction
        .execute("DELETE FROM network_policy", [])
        .map_err(StateError::database)?;
    transaction
        .execute("DELETE FROM client_global_route_prefixes", [])
        .map_err(StateError::database)?;

    for (position, interface) in state.interfaces.iter().enumerate() {
        let interface_id = interface.id.to_string();
        transaction
            .execute(
                "INSERT INTO managed_interfaces
                     (id, name, ownership, lifecycle, admin_up, private_key, listen_port,
                      manage_all_peers, position)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    interface_id,
                    interface.name.as_str(),
                    ownership_label(interface.ownership),
                    lifecycle_label(interface.lifecycle),
                    interface.admin_up.map(i64::from),
                    interface.private_key.expose_secret(),
                    interface.listen_port.map(i64::from),
                    i64::from(interface.manage_all_peers),
                    position as i64,
                ],
            )
            .map_err(StateError::database)?;

        insert_prefixes(
            transaction,
            Some(&interface_id),
            &prefix_strings(&interface.tunnel_prefixes),
            "INSERT INTO interface_tunnel_prefixes (interface_id, prefix, position) VALUES (?1, ?2, ?3)",
            "",
        )?;

        for (index, address) in interface.addresses.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO interface_addresses (interface_id, address, presence, position)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![
                        interface_id,
                        address.address.to_string(),
                        presence_label(address.presence),
                        index as i64,
                    ],
                )
                .map_err(StateError::database)?;
        }

        for (index, route) in interface.routes.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO managed_routes (interface_id, destination, gateway, presence, position)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        interface_id,
                        route.destination.to_string(),
                        route.gateway.map(|gateway| gateway.to_string()),
                        presence_label(route.presence),
                        index as i64,
                    ],
                )
                .map_err(StateError::database)?;
        }

        for (index, peer) in interface.peers.iter().enumerate() {
            let peer_id = peer.id.to_string();
            transaction
                .execute(
                    "INSERT INTO peers
                         (id, interface_id, public_key, private_key, preshared_key,
                          persistent_keepalive_seconds, endpoint, position)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        peer_id,
                        interface_id,
                        peer.public_key.expose(),
                        peer.private_key.as_ref().map(|key| key.expose_secret()),
                        peer.preshared_key.as_ref().map(|key| key.expose_secret()),
                        peer.persistent_keepalive_seconds.map(i64::from),
                        peer.endpoint.map(|endpoint| endpoint.to_string()),
                        index as i64,
                    ],
                )
                .map_err(StateError::database)?;

            insert_prefixes(
                transaction,
                Some(&peer_id),
                &prefix_strings(&peer.allowed_ips),
                "INSERT INTO peer_allowed_ips (peer_id, prefix, position) VALUES (?1, ?2, ?3)",
                "",
            )?;

            for (client_index, client) in interface.clients.iter().enumerate() {
                if client.peer_id != peer.id {
                    continue;
                }
                let client_id = client.id.to_string();
                transaction
                    .execute(
                        "INSERT INTO clients (id, interface_id, peer_id, assigned_address, position, assigned_ipv6_address)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            client_id,
                            interface_id,
                            peer_id,
                            client.assigned_address.to_string(),
                            client_index as i64,
                            client.assigned_ipv6_address.map(|address| address.to_string()),
                        ],
                    )
                    .map_err(StateError::database)?;
                insert_prefixes(
                    transaction,
                    Some(&client_id),
                    &prefix_strings(&client.route_policy.prefixes),
                    "INSERT INTO client_route_prefixes (client_id, prefix, position) VALUES (?1, ?2, ?3)",
                    "",
                )?;
            }
        }
    }

    insert_prefixes(
        transaction,
        None,
        &prefix_strings(&state.client_routes.prefixes),
        "",
        "INSERT INTO client_global_route_prefixes (position, prefix) VALUES (?1, ?2)",
    )?;

    if let Some(policy) = &state.network_policy {
        transaction
            .execute(
                "INSERT INTO network_policy
                     (singleton, wireguard_interface, ipv4_forwarding_required, egress_interface, masquerade,
                      ipv6_forwarding_required)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    policy.wireguard_interface.as_str(),
                    i64::from(policy.ipv4_forwarding_required),
                    policy.egress_interface.as_str(),
                    i64::from(policy.masquerade),
                    i64::from(policy.ipv6_forwarding_required),
                ],
            )
            .map_err(StateError::database)?;
        insert_prefixes(
            transaction,
            None,
            &prefix_strings(&policy.source_prefixes),
            "",
            "INSERT INTO network_policy_source_prefixes (position, prefix) VALUES (?1, ?2)",
        )?;
    }

    Ok(())
}

/// Inserts an ordered, optionally foreign-key-scoped prefix list.
fn insert_prefixes(
    transaction: &Transaction<'_>,
    key: Option<&str>,
    prefixes: &[String],
    keyed_statement: &str,
    unkeyed_statement: &str,
) -> Result<(), StateError> {
    for (index, prefix) in prefixes.iter().enumerate() {
        let position = index as i64;
        match key {
            Some(key) => transaction
                .execute(keyed_statement, rusqlite::params![key, prefix, position])
                .map_err(StateError::database)?,
            None => transaction
                .execute(unkeyed_statement, rusqlite::params![position, prefix])
                .map_err(StateError::database)?,
        };
    }
    Ok(())
}

/// Reads one ordered prefix column.
fn query_prefixes(connection: &Connection, sql: &str) -> Result<Vec<String>, StateError> {
    let mut statement = connection.prepare(sql).map_err(StateError::database)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(StateError::database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StateError::database)
}

/// Reads an ordered, foreign-key-scoped prefix column.
fn query_prefixes_for(
    connection: &Connection,
    sql: &str,
    key: &str,
) -> Result<Vec<NetworkPrefix>, StateError> {
    let mut statement = connection.prepare(sql).map_err(StateError::database)?;
    let rows = statement
        .query_map([key], |row| row.get::<_, String>(0))
        .map_err(StateError::database)?;
    let values = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(StateError::database)?;
    values.iter().map(|value| parse_prefix(value)).collect()
}
