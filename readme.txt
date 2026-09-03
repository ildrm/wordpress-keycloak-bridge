=== WP Keycloak Bridge ===
Contributors: openai
Tags: keycloak, oidc, sso, oauth2, authentication
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPLv2 or later

Secure OpenID Connect integration between WordPress and Keycloak.

== Features ==
* Authorization Code flow with PKCE, state binding and nonce validation.
* Keycloak discovery and JWKS key rotation.
* JIT user provisioning and verified-email account linking.
* Realm role, client role, and group to WordPress role mapping.
* Access rules and profile synchronization.
* RP-initiated logout and OIDC backchannel logout.
* Optional Keycloak JWT bearer authentication for WordPress REST API with an explicit configurable audience.
* Health/diagnostic endpoint for administrators.
* Multisite-aware user membership handling.

== Setup ==
1. Activate the plugin and open Settings > Keycloak.
2. Enter Keycloak base URL, realm, client ID, and optional client secret.
3. In Keycloak, configure the plugin's displayed OIDC callback URL as a valid redirect URI.
4. Configure the displayed backchannel logout URL on the Keycloak client if desired.
5. Keep Standard Flow enabled on the Keycloak client. PKCE S256 is used automatically.
6. Save settings and test login before enabling Force mode.

== Security notes ==
* HTTPS is required for non-local Keycloak URLs.
* JWT verification supports Keycloak RSA signatures RS256/RS384/RS512.
* Client secrets, tokens, and authorization codes are not written to debug logs.
* Access, refresh, and ID tokens are not persisted by the plugin.
* Automatic linking to privileged WordPress accounts is off by default.
* WordPress password login and password reset are disabled by default for Keycloak-linked users.
* Keep a tested local break-glass administrator account before enabling Force mode. To permit local login during an outage, temporarily define `WPKC_ALLOW_LOCAL_LOGIN` as true in wp-config.php; remove it immediately after recovery.

== Role mapping syntax ==
realm:wordpress-admin=administrator
client:editor=editor
group:/writers=author

Only roles managed by this plugin are removed during later synchronization; unrelated WordPress roles are preserved.
