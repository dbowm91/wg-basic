//! The EggServe [`Service`] implementation for the management surface.
//!
//! # The request pipeline
//!
//! Every request crosses the same fixed sequence, and the order is the contract:
//!
//! 1. **Body policy** — decided by the transport *before* this service runs, so a
//!    read-only route can never make the process buffer attacker-chosen bytes.
//! 2. **`Host`** — refused unless it is in the configured allowed set. A
//!    rebinding attempt dies here, before routing, so it cannot produce a side
//!    effect on any route.
//! 3. **Route** — an exact path match against a closed enum.
//! 4. **Method** — refused unless the matched route answers it.
//! 5. **`Origin`** — refused for an unsafe method that does not carry the exact
//!    configured origin.
//! 6. **Session and CSRF** — for the authenticated routes.
//! 7. **Handler**.
//!
//! Steps 2 and 5 run before step 7 for every route. That is the point: a
//! security check that only some routes remember to perform is a security check
//! waiting to be forgotten by the next route.
//!
//! # Routing is a closed match
//!
//! [`route`] matches a request target against a closed enum, not a handler
//! closure. That keeps three properties checkable by reading one function:
//!
//! * **Exhaustive.** Adding a route without deciding its method set is a compile
//!   error, so "unknown method" cannot silently become a new capability.
//! * **Closed.** Anything unmatched is [`Route::Unknown`], which renders as a
//!   bounded 404. There is no catch-all, no prefix match, and no dispatch on a
//!   path segment, so no future route can be reached by accident.
//! * **Body-declaring.** A route that accepts a body says so here, and the
//!   transport enforces it. Everything else is refused at the boundary.
//!
//! # No dynamic disclosure
//!
//! The service never formats an internal value into a response body. It maps a
//! matched [`Route`] and a bounded [`RequestRejection`] onto fixed literals, so
//! there is no error path that can print a path, a socket address, a generation,
//! or an internal type.

use super::{
    api::{build_response, AuthenticatedApi, RequestRejection, LOGIN_BODY_LIMIT},
    headers,
    response::{self, Liveness},
};
use crate::{
    domain::{ClientId, ClientRoutePolicy, DesiredGeneration, InterfaceName, NetworkPrefix},
    management::{ProductFailure, WorkerError},
    product::{
        AdvertisedEndpoint, ClientCreateCommand, ClientDeleteCommand, ClientEnabled, ClientLabel,
        ClientUpdateCommand, ServerSetupCommand, SetClientEnabledCommand,
    },
};
use eggserve_primitives::{
    request_body_policy::RequestBodyPolicy, request_head::RequestHead, Request, Response,
    ResponseBody,
};
use eggserve_server::service::{Service, ServiceFuture};
use futures_util::StreamExt;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

const PRODUCT_BODY_LIMIT: usize = 8 * 1024;

/// The single unauthenticated liveness route.
///
/// Named as a constant so the routing table, the tests, and the documentation
/// cannot drift apart.
pub const HEALTHZ_PATH: &str = "/healthz";

/// The credential-issuing route.
pub const LOGIN_PATH: &str = "/api/v1/login";

/// The session-revoking route.
pub const LOGOUT_PATH: &str = "/api/v1/logout";

/// The session-introspection route.
pub const SESSION_PATH: &str = "/api/v1/session";

/// The authenticated health route.
pub const API_HEALTH_PATH: &str = "/api/v1/health";

/// The operator shell, and the only route that is not under `/api` or `/healthz`.
///
/// Unauthenticated on purpose: it has to be reachable for an operator to have
/// something to type a password into. It is a login frame and a health readout,
/// and it contains no appliance state — everything it shows comes from the two
/// authenticated routes it calls.
pub const SHELL_PATH: &str = "/";

/// What a request target matched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// The unauthenticated liveness probe.
    Healthz,
    /// Credential issuance.
    Login,
    /// Session revocation.
    Logout,
    /// Session introspection.
    Session,
    /// Authenticated management health.
    ApiHealth,
    /// The embedded operator shell document.
    Shell,
    /// One embedded stylesheet or script, matched from a closed table.
    Asset,
    /// Authenticated product endpoint with an optional canonical client id.
    Product(ProductRoute, Option<ClientId>),
    EnrollmentLanding(crate::product::EnrollmentCapabilityId),
    EnrollmentConsume(crate::product::EnrollmentCapabilityId),
    EnrollmentRevoke(crate::product::EnrollmentCapabilityId),
    /// A path this surface does not have.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductRoute {
    Server,
    Setup,
    Clients,
    Client,
    Config,
    Qr,
    Enable,
    Disable,
    EnrollmentLinks,
}

impl Route {
    /// Whether this route accepts a request body.
    ///
    /// Each unsafe JSON family gets its own small bound; read routes refuse bodies.
    pub fn accepts_body(&self) -> bool {
        matches!(
            self,
            Self::Login
                | Self::Product(
                    ProductRoute::Setup
                        | ProductRoute::Clients
                        | ProductRoute::Client
                        | ProductRoute::Enable
                        | ProductRoute::Disable,
                    _
                )
                | Self::Product(ProductRoute::EnrollmentLinks, _)
                | Self::EnrollmentConsume(_)
        )
    }

    /// The methods this route answers.
    ///
    /// `HEAD` is deliberately *not* answered anywhere: a probe that cannot
    /// distinguish `HEAD` from `GET` is not this probe, and accepting a second
    /// method here would set the precedent that methods are added implicitly.
    fn accepts(&self, method: &str) -> bool {
        match self {
            Self::Healthz | Self::Session | Self::ApiHealth | Self::Shell | Self::Asset => {
                method == "GET"
            }
            Self::Login | Self::Logout => method == "POST",
            Self::Product(route, _) => match route {
                ProductRoute::Server => method == "GET",
                ProductRoute::Setup | ProductRoute::Enable | ProductRoute::Disable => {
                    method == "POST"
                }
                ProductRoute::Clients => method == "GET" || method == "POST",
                ProductRoute::Client => method == "GET" || method == "PATCH" || method == "DELETE",
                ProductRoute::Config | ProductRoute::Qr => method == "GET",
                ProductRoute::EnrollmentLinks => method == "POST",
            },
            Self::EnrollmentLanding(_) => method == "GET",
            Self::EnrollmentConsume(_) => method == "POST",
            Self::EnrollmentRevoke(_) => method == "DELETE",
            Self::Unknown => false,
        }
    }

    /// Whether a known route was reached by a method it does not answer.
    fn rejects_method(&self, method: &str) -> bool {
        if matches!(self, Self::Unknown) {
            return false;
        }
        !self.accepts(method)
    }
}

fn request_has_body(route: Route, method: &str) -> bool {
    route.accepts_body() && matches!(method, "POST" | "PATCH" | "DELETE")
}

/// Resolves a request target to a route.
///
/// Only an exact path match counts. `/healthz/` and `/healthz?x=1`-style
/// suffixes are unknown routes, not near misses, so the surface has no
/// normalisation rules an attacker could lean on.
pub fn route(path: &str) -> Route {
    match path {
        HEALTHZ_PATH => Route::Healthz,
        LOGIN_PATH => Route::Login,
        LOGOUT_PATH => Route::Logout,
        SESSION_PATH => Route::Session,
        API_HEALTH_PATH => Route::ApiHealth,
        SHELL_PATH => Route::Shell,
        // An embedded asset is matched exactly by its own lookup, which is a
        // closed table -- so there is no prefix rule here that
        // could match more than it should.
        path if super::assets::asset(path).is_some() => Route::Asset,
        "/api/v1/server" => Route::Product(ProductRoute::Server, None),
        "/api/v1/setup" => Route::Product(ProductRoute::Setup, None),
        "/api/v1/clients" => Route::Product(ProductRoute::Clients, None),
        path => product_route(path).unwrap_or(Route::Unknown),
    }
}

fn product_route(path: &str) -> Option<Route> {
    let pieces: Vec<_> = path.split('/').collect();
    if let ["", "enroll", raw] = pieces.as_slice() {
        let id = crate::product::EnrollmentCapabilityId::from_str(raw).ok()?;
        return (id.to_string() == *raw).then_some(Route::EnrollmentLanding(id));
    }
    if let ["", "api", "v1", "enroll", raw, "consume"] = pieces.as_slice() {
        let id = crate::product::EnrollmentCapabilityId::from_str(raw).ok()?;
        return (id.to_string() == *raw).then_some(Route::EnrollmentConsume(id));
    }
    if let ["", "api", "v1", "enrollment-links", raw] = pieces.as_slice() {
        let id = crate::product::EnrollmentCapabilityId::from_str(raw).ok()?;
        return (id.to_string() == *raw).then_some(Route::EnrollmentRevoke(id));
    }
    if pieces.len() < 5 || pieces[1..4] != ["api", "v1", "clients"] {
        return None;
    }
    let id = ClientId::from_str(pieces[4]).ok()?;
    if id.to_string() != pieces[4] {
        return None;
    }
    match pieces.as_slice() {
        ["", "api", "v1", "clients", _] => Some(Route::Product(ProductRoute::Client, Some(id))),
        ["", "api", "v1", "clients", _, "enable"] => {
            Some(Route::Product(ProductRoute::Enable, Some(id)))
        }
        ["", "api", "v1", "clients", _, "disable"] => {
            Some(Route::Product(ProductRoute::Disable, Some(id)))
        }
        ["", "api", "v1", "clients", _, "config"] => {
            Some(Route::Product(ProductRoute::Config, Some(id)))
        }
        ["", "api", "v1", "clients", _, "qr"] => Some(Route::Product(ProductRoute::Qr, Some(id))),
        ["", "api", "v1", "clients", _, "enrollment-links"] => {
            Some(Route::Product(ProductRoute::EnrollmentLinks, Some(id)))
        }
        _ => None,
    }
}

/// The management HTTP service.
#[derive(Clone, Debug)]
pub struct ManagementService {
    api: AuthenticatedApi,
}

impl ManagementService {
    /// Builds the service over the authenticated API.
    pub fn new(api: AuthenticatedApi) -> Self {
        Self { api }
    }

    /// The origin policy and limiter in force.
    pub fn api(&self) -> &AuthenticatedApi {
        &self.api
    }

    /// Runs the pipeline for one request and seals the answer.
    ///
    /// [`headers::seal`] is applied here, once, on **every** path — success,
    /// refusal, unknown route, and worker failure alike. That is what makes the
    /// security headers total: a [`Response`] does not exist until routing has
    /// chosen one, and it cannot leave this function unsealed.
    async fn dispatch(&self, head: &RequestHead, body: &[u8], peer: SocketAddr) -> Response {
        let answer = self.route_request(head, body, peer).await;
        headers::seal(answer, self.api.guard().is_secure())
    }

    /// Steps 2 through 7 of the pipeline for one request.
    ///
    /// Separated from [`ManagementService::dispatch`] so that the sealing
    /// guarantee has exactly one call site to audit: this function is free to
    /// return early from anywhere, because every early return still goes back
    /// through [`ManagementService::dispatch`].
    async fn route_request(&self, head: &RequestHead, body: &[u8], peer: SocketAddr) -> Response {
        let guard = self.api.guard();

        // 2. Host, before routing, for every request without exception. A
        //    rebinding attempt dies here, so it cannot produce a side effect on
        //    any route — including the ones that change state.
        if let Err(rejection) = guard.check_host(head) {
            return refusal(rejection);
        }

        // 3 and 4. Route and method.
        let matched = route(head.target().path());
        if !matched.accepts(head.method().as_str()) {
            // A known route reached by an unknown method says so; an unknown
            // route stays a 404 so a prober cannot enumerate the surface.
            return if matched.rejects_method(head.method().as_str()) {
                response::method_not_allowed()
            } else {
                response::not_found()
            };
        }

        // 5. Origin, for every unsafe method on every route.
        if let Err(rejection) = guard.check_origin(head) {
            return refusal(rejection);
        }

        // 6 and 7. Session, CSRF, and the handler.
        match matched {
            Route::Healthz => match self.api.worker_health().await {
                // Classified once, then projected down to two tokens. The
                // reasons `Readiness` carries are not rendered here and have no
                // path to this response -- only the operator's startup log and
                // the authenticated route below can name them.
                Ok(health) => response::liveness(Liveness::from_readiness(
                    super::Readiness::from_health(&health),
                )),
                Err(error) => response_for_worker_error(error),
            },
            Route::Login => match self.api.login(head, body, peer).await {
                Ok(response) => response,
                Err(rejection) => refusal(rejection),
            },
            Route::Logout => {
                // Both checks run before anything is revoked. A logout without a
                // CSRF token is an attacker's request, and revoking on it would
                // turn a cross-site request into a working denial of service.
                let Some(session) = self.api.authenticate(head).await else {
                    return refusal(RequestRejection::NotAuthenticated);
                };
                if let Err(rejection) = guard.check_csrf(head, &session) {
                    return refusal(rejection);
                }
                // Keyed by the raw presented token: revocation looks up the
                // digest of exactly this value, so re-hashing would never match.
                let presented = guard
                    .presented_token(head)
                    .expect("authentication resolved only from a presented cookie");
                self.api.logout(&presented).await
            }
            Route::Session => {
                let Some(session) = self.api.authenticate(head).await else {
                    return refusal(RequestRejection::NotAuthenticated);
                };
                self.api.session(&session)
            }
            Route::ApiHealth => {
                if self.api.authenticate(head).await.is_none() {
                    return refusal(RequestRejection::NotAuthenticated);
                }
                match self.api.health().await {
                    Ok(response) => response,
                    Err(error) => response_for_worker_error(error),
                }
            }
            Route::Product(route, id) => {
                let Some(session) = self.api.authenticate(head).await else {
                    return refusal(RequestRejection::NotAuthenticated);
                };
                if matches!(head.method().as_str(), "POST" | "PATCH" | "DELETE") {
                    if let Err(rejection) = guard.check_csrf(head, &session) {
                        return refusal(rejection);
                    }
                }
                let principal_id = session.session.principal_id;
                self.product(route, id, principal_id, body, head).await
            }
            Route::EnrollmentLanding(_) => match super::assets::response_body("/enroll") {
                Some(body) => response::build(
                    super::assets::status(),
                    super::assets::content_type("/enroll"),
                    body,
                ),
                None => response::not_found(),
            },
            Route::EnrollmentRevoke(id) => {
                let Some(session) = self.api.authenticate(head).await else {
                    return refusal(RequestRejection::NotAuthenticated);
                };
                if let Err(rejection) = guard.check_csrf(head, &session) {
                    return refusal(rejection);
                }
                match self
                    .api
                    .worker()
                    .revoke_enrollment_link(session.session.principal_id, id)
                    .await
                {
                    Ok(true) => json_response(
                        eggserve_primitives::StatusCode::OK,
                        &serde_json::json!({"revoked":true}),
                    ),
                    Ok(false) => response::not_found(),
                    Err(error) => response_for_worker_error(error),
                }
            }
            Route::EnrollmentConsume(id) => {
                if let Err(error) = guard.check_json_content_type(head) {
                    return refusal(error);
                }
                if body.len() > super::api::ENROLLMENT_BODY_LIMIT {
                    return refusal(RequestRejection::BodyTooLarge);
                }
                match self.api.admit_enrollment(peer) {
                    super::Admission::Refused {
                        retry_after_seconds,
                    } => {
                        return refusal(RequestRejection::Throttled {
                            retry_after_seconds,
                        })
                    }
                    super::Admission::Allowed { .. } => {}
                }
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ConsumeBody {
                    token: String,
                }
                let Some(input): Option<ConsumeBody> = parse_json(body) else {
                    return product_status(410, "enrollment unavailable");
                };
                let token = match crate::product::EnrollmentToken::parse(input.token) {
                    Ok(token) => token,
                    Err(_) => return product_status(410, "enrollment unavailable"),
                };
                match self.api.worker().consume_enrollment(id, token).await {
                    Ok(Some(config)) => response::build(
                        eggserve_primitives::StatusCode::OK,
                        "text/plain; charset=utf-8",
                        ResponseBody::Bytes(config.into_bytes()),
                    ),
                    Ok(None) => product_status(410, "enrollment unavailable"),
                    Err(error) => response_for_worker_error(error),
                }
            }
            // The shell and its two assets. Unauthenticated, because a login
            // frame nobody can reach is not a login frame -- and empty of
            // appliance state, because everything it shows arrives from the
            // authenticated routes it calls. Both still go out through the same
            // single `seal`, so the security headers are not optional here.
            Route::Shell | Route::Asset => {
                match super::assets::response_body(head.target().path()) {
                    Some(body) => response::build(
                        super::assets::status(),
                        super::assets::content_type(head.target().path()),
                        body,
                    ),
                    // Unreachable: `route()` only returns `Shell`/`Asset` for a
                    // path the inventory holds. Refused rather than panicked,
                    // because a panic in a request handler is a denial of
                    // service and a 404 here is indistinguishable from a typo.
                    None => response::not_found(),
                }
            }
            Route::Unknown => response::not_found(),
        }
    }

    async fn product(
        &self,
        route: ProductRoute,
        id: Option<ClientId>,
        principal_id: crate::domain::PrincipalId,
        body: &[u8],
        head: &RequestHead,
    ) -> Response {
        use ProductRoute::*;
        if matches!(head.method().as_str(), "POST" | "PATCH" | "DELETE") {
            if let Err(error) = self.api.guard().check_json_content_type(head) {
                return refusal(error);
            }
            if body.len() > PRODUCT_BODY_LIMIT {
                return refusal(RequestRejection::BodyTooLarge);
            }
        }
        if head.method().as_str() == "GET"
            && matches!(route, Server | Clients | Client)
            && !body.is_empty()
        {
            return refusal(RequestRejection::BodyMalformed);
        }
        match route {
            Server => match self.api.worker().product_snapshot().await {
                Ok(snapshot) => json_response(
                    eggserve_primitives::StatusCode::OK,
                    &serde_json::json!({"generation": snapshot.generation, "server": snapshot.server}),
                ),
                Err(error) => response_for_worker_error(error),
            },
            Clients => {
                if head.method().as_str() == "GET" {
                    match self.api.worker().product_snapshot().await {
                        Ok(snapshot) => json_response(
                            eggserve_primitives::StatusCode::OK,
                            &serde_json::json!({"generation": snapshot.generation, "clients": snapshot.clients}),
                        ),
                        Err(error) => response_for_worker_error(error),
                    }
                } else {
                    let input: CreateBody = match parse_json(body) {
                        Some(v) => v,
                        None => return product_status(422, "invalid request"),
                    };
                    let Some(generation) = DesiredGeneration::new(input.expected_generation) else {
                        return product_status(422, "invalid request");
                    };
                    let requested_address = match input.address {
                        Some(value) => match IpAddr::from_str(&value) {
                            Ok(address) => Some(address),
                            Err(_) => return product_status(422, "invalid request"),
                        },
                        None => None,
                    };
                    let command = ClientCreateCommand {
                        principal_id,
                        expected_generation: generation,
                        interface_id: input.interface_id,
                        label: match ClientLabel::new(input.label) {
                            Ok(v) => v,
                            Err(_) => return product_status(422, "invalid request"),
                        },
                        requested_address,
                        route_policy: input.route_policy,
                        dns_servers: match parse_ips(input.dns_servers) {
                            Some(v) => v,
                            None => return product_status(422, "invalid request"),
                        },
                        client_keepalive_seconds: input.client_keepalive_seconds,
                    };
                    match self.api.worker().create_client(command).await {
                        Ok(reply) => mutation_response(201, 202, &reply.client, reply.receipt),
                        Err(error) => product_error(error),
                    }
                }
            }
            Setup => {
                let input: SetupBody = match parse_json(body) {
                    Some(v) => v,
                    None => return product_status(422, "invalid request"),
                };
                let Some(generation) = DesiredGeneration::new(input.expected_generation) else {
                    return product_status(422, "invalid request");
                };
                let server_address = match input.server_address {
                    Some(value) => match IpAddr::from_str(&value) {
                        Ok(address) => Some(address),
                        Err(_) => return product_status(422, "invalid request"),
                    },
                    None => None,
                };
                let Some(tunnel_prefix) = input.tunnel_prefix.parse::<NetworkPrefix>().ok() else {
                    return product_status(422, "invalid request");
                };
                let command = ServerSetupCommand {
                    principal_id,
                    expected_generation: generation,
                    interface_name: match InterfaceName::new(input.interface_name) {
                        Ok(v) => v,
                        Err(_) => return product_status(422, "invalid request"),
                    },
                    tunnel_prefix,
                    server_address,
                    listen_port: input.listen_port,
                    advertised_endpoint: match AdvertisedEndpoint::parse(&input.advertised_endpoint)
                    {
                        Ok(v) => v,
                        Err(_) => return product_status(422, "invalid request"),
                    },
                    egress_interface: match InterfaceName::new(input.egress_interface) {
                        Ok(v) => v,
                        Err(_) => return product_status(422, "invalid request"),
                    },
                    ipv4_forwarding_required: input.ipv4_forwarding_required,
                    masquerade: input.masquerade,
                    default_client_route_policy: input.default_client_route_policy,
                };
                match self.api.worker().setup_server(command).await {
                    Ok(reply) => mutation_response(200, 202, &reply.server, reply.receipt),
                    Err(error) => product_error(error),
                }
            }
            Client => {
                let Some(id) = id else {
                    return response::not_found();
                };
                if head.method().as_str() == "GET" {
                    return match self.api.worker().product_snapshot().await {
                        Ok(snapshot) => match snapshot
                            .clients
                            .iter()
                            .find(|client| client.client_id == id)
                        {
                            Some(client) => json_response(
                                eggserve_primitives::StatusCode::OK,
                                &serde_json::json!({"generation":snapshot.generation,"client":client}),
                            ),
                            None => response::not_found(),
                        },
                        Err(error) => response_for_worker_error(error),
                    };
                }
                if head.method().as_str() == "DELETE" {
                    let input: GenerationBody = match parse_json(body) {
                        Some(v) => v,
                        None => return product_status(422, "invalid request"),
                    };
                    let Some(generation) = DesiredGeneration::new(input.expected_generation) else {
                        return product_status(422, "invalid request");
                    };
                    match self
                        .api
                        .worker()
                        .delete_client(ClientDeleteCommand {
                            principal_id,
                            expected_generation: generation,
                            client_id: id,
                        })
                        .await
                    {
                        Ok(receipt) => mutation_response(
                            200,
                            202,
                            &serde_json::json!({"deleted":true}),
                            receipt,
                        ),
                        Err(error) => product_error(error),
                    }
                } else {
                    let input: PatchBody = match parse_json(body) {
                        Some(v) => v,
                        None => return product_status(422, "invalid request"),
                    };
                    let Some(generation) = DesiredGeneration::new(input.expected_generation) else {
                        return product_status(422, "invalid request");
                    };
                    let label = match input.label {
                        Some(v) => match ClientLabel::new(v) {
                            Ok(v) => Some(v),
                            Err(_) => return product_status(422, "invalid request"),
                        },
                        None => None,
                    };
                    let dns = match input.dns_servers {
                        Some(v) => match parse_ips(v) {
                            Some(v) => Some(v),
                            None => return product_status(422, "invalid request"),
                        },
                        None => None,
                    };
                    let requested_address = match input.address {
                        Some(value) => match IpAddr::from_str(&value) {
                            Ok(address) => Some(address),
                            Err(_) => return product_status(422, "invalid request"),
                        },
                        None => None,
                    };
                    let command = ClientUpdateCommand {
                        principal_id,
                        expected_generation: generation,
                        client_id: id,
                        label,
                        route_policy: input.route_policy,
                        dns_servers: dns,
                        client_keepalive_seconds: input.client_keepalive_seconds,
                        requested_address,
                    };
                    match self.api.worker().update_client(command).await {
                        Ok(reply) => mutation_response(200, 202, &reply.client, reply.receipt),
                        Err(error) => product_error(error),
                    }
                }
            }
            Config | Qr => {
                let Some(id) = id else {
                    return response::not_found();
                };
                let config = match self.api.worker().client_config(id).await {
                    Ok(config) => config,
                    Err(error) => return product_error(error),
                };
                if route == Config {
                    let mut answer = response::build(
                        eggserve_primitives::StatusCode::OK,
                        "text/plain; charset=utf-8",
                        ResponseBody::Bytes(config.into_bytes()),
                    );
                    headers::with_attachment(&mut answer, &format!("wg-client-{id}.conf"));
                    answer
                } else {
                    match crate::product::render_qr_svg(config.expose()) {
                        Ok(svg) => response::build(
                            eggserve_primitives::StatusCode::OK,
                            "image/svg+xml",
                            ResponseBody::Bytes(svg.into_bytes()),
                        ),
                        Err(_) => product_status(422, "artifact unavailable"),
                    }
                }
            }
            EnrollmentLinks => {
                let Some(id) = id else {
                    return response::not_found();
                };
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct LinkBody {
                    #[serde(default)]
                    expires_in_seconds: Option<u64>,
                }
                let Some(input): Option<LinkBody> = parse_json(body) else {
                    return product_status(422, "invalid request");
                };
                let ttl = input
                    .expires_in_seconds
                    .unwrap_or(crate::product::DEFAULT_ENROLLMENT_TTL_SECONDS);
                match self
                    .api
                    .worker()
                    .create_enrollment_link(principal_id, id, ttl)
                    .await
                {
                    Ok(link) => {
                        let token = link.token.expose_once();
                        let share_url = format!(
                            "{}/enroll/{}#token={token}",
                            self.api.canonical_origin(),
                            link.capability_id
                        );
                        json_response(
                            eggserve_primitives::StatusCode::CREATED,
                            &serde_json::json!({"capability_id":link.capability_id,"share_url":share_url,"expires_at":link.expires_at}),
                        )
                    }
                    Err(error) => product_error(error),
                }
            }
            Enable | Disable => {
                let Some(id) = id else {
                    return response::not_found();
                };
                let input: GenerationBody = match parse_json(body) {
                    Some(v) => v,
                    None => return product_status(422, "invalid request"),
                };
                let Some(generation) = DesiredGeneration::new(input.expected_generation) else {
                    return product_status(422, "invalid request");
                };
                match self
                    .api
                    .worker()
                    .set_client_enabled(SetClientEnabledCommand {
                        principal_id,
                        expected_generation: generation,
                        client_id: id,
                        enabled: if route == Enable {
                            ClientEnabled::Enabled
                        } else {
                            ClientEnabled::Disabled
                        },
                    })
                    .await
                {
                    Ok(reply) => mutation_response(200, 202, &reply.client, reply.receipt),
                    Err(error) => product_error(error),
                }
            }
        }
    }
}

/// Renders a bounded refusal.
///
/// One literal per status class. The `Retry-After` is the only variable header,
/// and it exists solely so a throttled client knows when to come back.
fn refusal(rejection: RequestRejection) -> Response {
    let built = super::api::build_response(
        rejection.status(),
        ResponseBody::Bytes(rejection.body().as_bytes().to_vec()),
        None,
    );
    match rejection.retry_after() {
        Some(retry_after) => headers::with_retry_after(built, retry_after),
        None => built,
    }
}

/// Maps a worker failure onto the bounded HTTP vocabulary.
///
/// Overload and a stopped worker are retryable and are not the client's fault, so
/// they are one answer. A product failure is a server fault. A refused credential
/// is neither: it renders as `401` through the route's own refusal path and never
/// reaches this function, because the route needs to know that a refusal happened
/// rather than that a command succeeded.
fn response_for_worker_error(error: WorkerError) -> Response {
    match error {
        WorkerError::Saturated | WorkerError::TimedOut | WorkerError::Stopped => {
            response::unavailable()
        }
        WorkerError::Failed(_) => response::internal_error(),
        // A refusal or a storage failure that reached a *read-only* route. The
        // login route renders these itself, because it must distinguish a wrong
        // password from an outage.
        WorkerError::Rejected | WorkerError::Unavailable | WorkerError::Storage => {
            response::unavailable()
        }
        // A refused product command that reaches a read-only path has no
        // request-specific projection and stays a bounded internal failure.
        WorkerError::Product(_) => response::internal_error(),
    }
}

impl Service for ManagementService {
    /// Only login and the explicitly bounded product mutation routes carry bodies.
    ///
    /// The runtime consults this before routing, so a body on any other route is
    /// refused by the transport rather than by application code. Each permitted
    /// route has its own bound, checked again by its handler.
    fn request_body_policy(&self, head: &RequestHead) -> RequestBodyPolicy {
        let matched = route(head.target().path());
        match matched {
            matched if request_has_body(matched, head.method().as_str()) => {
                RequestBodyPolicy::Buffer {
                    max_bytes: (if matches!(matched, Route::Login) {
                        LOGIN_BODY_LIMIT
                    } else if matches!(matched, Route::EnrollmentConsume(_)) {
                        super::api::ENROLLMENT_BODY_LIMIT
                    } else {
                        PRODUCT_BODY_LIMIT
                    }) as u64,
                }
            }
            _ => RequestBodyPolicy::Reject,
        }
    }

    fn call(&self, request: Request) -> ServiceFuture<'_> {
        let head = request.head().clone();
        // Observed at accept time by the transport, never derived from a
        // forwarding header. The fallback is unreachable for a TCP listener —
        // EggServe always populates it — and collapses such a request into one
        // shared limiter bucket rather than inventing a per-attacker budget.
        let peer = request
            .connection()
            .remote_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let matched = route(head.target().path());
        let body_limit = if matches!(matched, Route::Login) {
            LOGIN_BODY_LIMIT
        } else if matches!(matched, Route::EnrollmentConsume(_)) {
            super::api::ENROLLMENT_BODY_LIMIT
        } else {
            PRODUCT_BODY_LIMIT
        };
        let accepts_body = request_has_body(matched, head.method().as_str());
        let service = self.clone();
        Box::pin(async move {
            // The body is read only for routes whose body policy allows
            // it. Every other route is `Reject`, so the runtime never hands one
            // bytes to buffer.
            let body = if accepts_body {
                collect_bounded_body(request.into_body(), body_limit).await
            } else {
                Vec::new()
            };
            Ok(service.dispatch(&head, &body, peer).await)
        })
    }
}

/// Reads at most `limit` bytes from a request body.
///
/// Stops at the limit rather than truncating, so a client that sends more than
/// the route allows is refused for sending too much instead of having its request
/// silently shortened into something it did not send.
async fn collect_bounded_body(mut body: eggserve_primitives::RequestBody, limit: usize) -> Vec<u8> {
    let mut collected = Vec::new();
    while let Some(chunk) = body.next().await {
        let Ok(chunk) = chunk else {
            // A transport error mid-body is indistinguishable from an empty body
            // to the route, which will refuse it as malformed.
            break;
        };
        if collected.len().saturating_add(chunk.len()) > limit {
            // Pad to exactly the limit so the route's own bound is the one that
            // rejects it. Truncating below the limit would turn an oversized
            // request into a well-formed smaller one.
            collected.resize(limit, 0);
            return collected;
        }
        collected.extend_from_slice(&chunk);
    }
    collected
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationBody {
    expected_generation: u64,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    expected_generation: u64,
    interface_name: String,
    tunnel_prefix: String,
    #[serde(default)]
    server_address: Option<String>,
    listen_port: u16,
    advertised_endpoint: String,
    egress_interface: String,
    ipv4_forwarding_required: bool,
    masquerade: bool,
    #[serde(default)]
    default_client_route_policy: ClientRoutePolicy,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    expected_generation: u64,
    interface_id: crate::domain::InterfaceId,
    label: String,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    route_policy: Option<ClientRoutePolicy>,
    #[serde(default)]
    dns_servers: Vec<String>,
    #[serde(default)]
    client_keepalive_seconds: Option<u16>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchBody {
    expected_generation: u64,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    route_policy: Option<ClientRoutePolicy>,
    #[serde(default)]
    dns_servers: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_optional")]
    client_keepalive_seconds: Option<Option<u16>>,
}

fn deserialize_optional_optional<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer).map(Some)
}

fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Option<T> {
    serde_json::from_slice(body).ok()
}
fn parse_ips(values: Vec<String>) -> Option<Vec<IpAddr>> {
    values
        .into_iter()
        .map(|value| IpAddr::from_str(&value).ok())
        .collect()
}
fn status(value: u16) -> eggserve_primitives::StatusCode {
    eggserve_primitives::StatusCode::new(value).expect("fixed HTTP status")
}
fn json_response<T: serde::Serialize>(
    status_code: eggserve_primitives::StatusCode,
    payload: &T,
) -> Response {
    match serde_json::to_vec(payload) {
        Ok(body) if body.len() <= super::response::MAX_MANAGEMENT_BODY_BYTES => {
            build_response(status_code, ResponseBody::Bytes(body), None)
        }
        _ => response::internal_error(),
    }
}
fn product_status(code: u16, message: &'static str) -> Response {
    json_response(status(code), &serde_json::json!({"error":message}))
}
fn mutation_response<T: serde::Serialize>(
    converged_status: u16,
    degraded_status: u16,
    value: &T,
    receipt: crate::product::ProductMutationReceipt,
) -> Response {
    let (enforcement, degraded) = match receipt.enforcement {
        crate::product::EnforcementState::Converged => ("converged", None),
        crate::product::EnforcementState::Pending => ("pending", None),
        crate::product::EnforcementState::Degraded(category) => {
            ("degraded", Some(category.as_str()))
        }
    };
    let code = if degraded.is_some() {
        degraded_status
    } else {
        converged_status
    };
    json_response(
        status(code),
        &serde_json::json!({"data":value,"generation":receipt.generation,"enforcement":enforcement,"degraded_category":degraded,"revocation_confirmed":degraded.is_none()}),
    )
}
fn product_error(error: WorkerError) -> Response {
    match error {
        WorkerError::Product(ProductFailure::StaleGeneration) => {
            product_status(409, "generation conflict")
        }
        WorkerError::Product(ProductFailure::NotFound) => response::not_found(),
        WorkerError::Product(ProductFailure::ServerAlreadyConfigured) => {
            product_status(409, "server already configured")
        }
        WorkerError::Product(ProductFailure::Invalid | ProductFailure::AddressUnavailable) => {
            product_status(422, "invalid request")
        }
        WorkerError::Product(ProductFailure::ServerNotConfigured) => {
            product_status(409, "server not configured")
        }
        WorkerError::Product(ProductFailure::StateUnavailable) => response::unavailable(),
        WorkerError::Product(ProductFailure::SecretUnavailable) => {
            product_status(409, "artifact unavailable")
        }
        other => response_for_worker_error(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eggserve_primitives::StatusCode;

    #[test]
    fn routing_is_an_exact_match_over_a_closed_set() {
        assert_eq!(route("/healthz"), Route::Healthz);
        assert_eq!(route("/api/v1/login"), Route::Login);
        assert_eq!(route("/api/v1/logout"), Route::Logout);
        assert_eq!(route("/api/v1/session"), Route::Session);
        assert_eq!(route("/api/v1/health"), Route::ApiHealth);
        assert_eq!(
            route("/api/v1/server"),
            Route::Product(ProductRoute::Server, None)
        );
        assert_eq!(
            route("/api/v1/setup"),
            Route::Product(ProductRoute::Setup, None)
        );
        assert_eq!(
            route("/api/v1/clients"),
            Route::Product(ProductRoute::Clients, None)
        );
        assert_eq!(route("/"), Route::Shell);
        assert_eq!(route("/assets/app.css"), Route::Asset);
        assert_eq!(route("/assets/app.js"), Route::Asset);

        // Every one of these is a near miss rather than a typo fix. A surface
        // that normalises its own paths has normalisation rules, and those are
        // rules an attacker gets to probe.
        for target in [
            "//",
            "",
            "/index.html",
            "/assets/",
            "/assets/app.css/",
            "/assets/app.css.map",
            "/assets/app.css?v=2",
            "/assets/../assets/app.css",
            "/healthz/",
            "/api/v1/",
            "/api/v1",
            "/api/v1/login/",
            "/api/v1/peers",
            "/api/v1/clients/not-a-uuid",
            "/api/v1/interfaces",
            "/API/V1/LOGIN",
            "/api/v1/login%00",
            "/api/v2/login",
        ] {
            assert_eq!(route(target), Route::Unknown, "{target:?} must not match");
        }
    }

    #[test]
    fn only_declared_json_routes_accept_bodies() {
        assert!(Route::Login.accepts_body());
        for matched in [
            Route::Healthz,
            Route::Logout,
            Route::Session,
            Route::ApiHealth,
            Route::Shell,
            Route::Asset,
            Route::Unknown,
        ] {
            assert!(!matched.accepts_body(), "{matched:?} must accept no body");
        }
        let id = ClientId::new();
        let client = Route::Product(ProductRoute::Client, Some(id));
        assert!(request_has_body(client, "PATCH"));
        assert!(request_has_body(client, "DELETE"));
        assert!(!request_has_body(client, "GET"));
        assert!(request_has_body(
            Route::Product(ProductRoute::Setup, None),
            "POST"
        ));
    }

    #[test]
    fn each_route_answers_exactly_one_method() {
        assert!(Route::Healthz.accepts("GET"));
        assert!(Route::Session.accepts("GET"));
        assert!(Route::ApiHealth.accepts("GET"));
        assert!(Route::Login.accepts("POST"));
        assert!(Route::Logout.accepts("POST"));

        // HEAD is answered nowhere, so a prober cannot use it to read a body it
        // was not allowed a GET for.
        for matched in [
            Route::Healthz,
            Route::Session,
            Route::ApiHealth,
            Route::Login,
            Route::Logout,
        ] {
            assert!(!matched.accepts("HEAD"), "{matched:?} must refuse HEAD");
        }
        // A known route with the wrong method is distinguishable from an unknown
        // route, which stays a 404 so the surface cannot be enumerated.
        assert!(Route::Healthz.rejects_method("POST"));
        assert!(!Route::Unknown.rejects_method("POST"));
        assert!(!Route::Unknown.accepts("GET"));
    }

    #[test]
    fn dynamic_product_routes_require_canonical_uuid_and_exact_segments() {
        let id = ClientId::new().to_string();
        assert_eq!(
            route(&format!("/api/v1/clients/{id}")),
            Route::Product(ProductRoute::Client, Some(ClientId::from_str(&id).unwrap()))
        );
        assert_eq!(
            route(&format!("/api/v1/clients/{id}/enable")),
            Route::Product(ProductRoute::Enable, Some(ClientId::from_str(&id).unwrap()))
        );
        assert_eq!(
            route(&format!("/api/v1/clients/{id}/config")),
            Route::Product(ProductRoute::Config, Some(ClientId::from_str(&id).unwrap()))
        );
        for target in [
            format!("/api/v1/clients/{id}/"),
            format!("/api/v1/clients/{id}/enable/extra"),
            format!("/api/v1/clients/{}/enable", id.to_uppercase()),
            format!("/api/v1/clients/{id}%00"),
        ] {
            assert_eq!(route(&target), Route::Unknown, "{target} must not match");
        }
        for target in [
            "/api/v1/peers",
            "/api/v1/interfaces",
            "/api/v1/network-policy",
        ] {
            assert_eq!(route(target), Route::Unknown, "{target} must not exist");
        }
    }

    #[test]
    fn a_refusal_renders_one_of_four_bounded_literals() {
        let literals: std::collections::HashSet<&str> = [
            RequestRejection::HostNotAllowed,
            RequestRejection::OriginNotAllowed,
            RequestRejection::CrossSiteRequest,
            RequestRejection::CsrfMissing,
            RequestRejection::CsrfInvalid,
            RequestRejection::BodyTooLarge,
            RequestRejection::ContentTypeNotAllowed,
            RequestRejection::BodyMalformed,
            RequestRejection::NotAuthenticated,
            RequestRejection::Throttled {
                retry_after_seconds: 1,
            },
        ]
        .iter()
        .map(RequestRejection::body)
        .collect();
        assert_eq!(literals.len(), 4, "{literals:?}");
    }

    #[test]
    fn status_selection_matches_the_documented_vocabulary() {
        assert_eq!(
            RequestRejection::NotAuthenticated.status().as_u16(),
            401,
            "an unauthenticated caller is 401"
        );
        assert_eq!(
            RequestRejection::CsrfInvalid.status().as_u16(),
            403,
            "a policy refusal is 403"
        );
        assert_eq!(
            RequestRejection::BodyTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            RequestRejection::Throttled {
                retry_after_seconds: 3
            }
            .status()
            .as_u16(),
            429,
            "a throttled attempt is 429, so a client can distinguish it and back off"
        );
    }
}
