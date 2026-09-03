# WP Keycloak Bridge

Secure OpenID Connect (OIDC) integration between WordPress and Keycloak.

WP Keycloak Bridge lets WordPress use Keycloak for interactive single sign-on, just-in-time user provisioning, profile and role synchronization, logout, backchannel logout, and optional bearer-token authentication for the WordPress REST API.

## Requirements

- WordPress **6.4 or newer**
- PHP **8.1 or newer**
- PHP OpenSSL support
- A Keycloak realm and client
- HTTPS for production WordPress and Keycloak deployments

The plugin rejects non-HTTPS Keycloak URLs except for `localhost`, `127.0.0.1`, and `::1` development environments.

## Features

- OpenID Connect Authorization Code flow
- PKCE using `S256`
- OIDC `state` and `nonce` validation
- Browser-bound login transaction protection
- Automatic OIDC discovery
- JWKS retrieval and cached signing-key rotation
- RSA JWT signature verification (`RS256`, `RS384`, `RS512`)
- Just-in-time WordPress user provisioning
- Safe linking by verified email
- Protection against automatic linking to privileged WordPress accounts
- Keycloak realm-role mapping to WordPress roles
- Keycloak client-role mapping to WordPress roles
- Keycloak group mapping to WordPress roles
- Optional role/group-based access restrictions
- Verified profile synchronization on login
- Optional disabling of local WordPress password login/reset for linked users
- Optional forced Keycloak login mode
- RP-initiated Keycloak logout
- OIDC backchannel logout with replay protection
- Optional Keycloak bearer-token authentication for the WordPress REST API
- Administrator-only connection/health diagnostics
- WordPress Multisite-aware site membership handling
- Emergency local-login escape hatch for administrators

## Installation

1. Upload the plugin directory to:

   ```text
   wp-content/plugins/wp-keycloak-bridge
   ```

   Alternatively, upload the plugin ZIP through **Plugins → Add Plugin → Upload Plugin** in WordPress.

2. Activate **WP Keycloak Bridge**.

3. Open **Settings → Keycloak**.

4. Enter your Keycloak URL, realm, client ID, and client secret if the client uses client authentication.

5. Copy the **OIDC callback URL** shown by the plugin and add it to the Keycloak client's valid redirect URIs.

6. If using backchannel logout, copy the **Backchannel logout URL** shown by the plugin and configure it on the Keycloak client.

7. Save the WordPress settings.

8. Run the connection test.

9. Test Keycloak login while the plugin is still in **Optional** mode.

10. Only enable **Force Keycloak login** after confirming that login, role mapping, and recovery access work correctly.

## Keycloak Client Configuration

Create or select an OpenID Connect client in the required Keycloak realm.

### Required settings

Use settings equivalent to the following:

| Keycloak setting | Value |
|---|---|
| Client type/protocol | OpenID Connect |
| Standard Flow | Enabled |
| Client ID | Same value configured in WordPress |
| Valid Redirect URI | Exact OIDC callback URL displayed under **Settings → Keycloak** |
| PKCE | `S256` is used automatically by the plugin |

If **Client authentication** is enabled in Keycloak, enter the resulting client secret in WordPress. If the client is public, leave the WordPress client-secret field empty.

### Post-logout redirect

When **Redirect WordPress logout through Keycloak** is enabled, the plugin uses Keycloak's discovered `end_session_endpoint` and sends a `post_logout_redirect_uri` together with the client ID.

Configure the Keycloak client to allow the WordPress URL or URLs that users may return to after logout. The exact Keycloak setting name can vary between Keycloak versions.

### Role and group claims

Interactive WordPress login uses claims from the **ID token**. Therefore, any Keycloak role or group you want to use for WordPress role mapping or access rules must be present in that ID token.

The plugin reads these claim locations:

```text
realm_access.roles
resource_access.<wordpress-client-id>.roles
groups
```

If your Keycloak client does not emit the required roles or groups in the ID token, add/configure the appropriate Keycloak protocol or client-scope mappers.

For group mapping, configure a Group Membership mapper so the `groups` claim is included in the ID token. If the same claims are also needed during REST bearer authentication, include them in the access token as well.

## WordPress Configuration

Open **Settings → Keycloak**.

### Keycloak URL

Base URL of the Keycloak server, without the realm path.

Example:

```text
https://sso.example.com
```

Do not enter:

```text
https://sso.example.com/realms/example
```

The plugin constructs the issuer as:

```text
<keycloak-url>/realms/<realm>
```

### Realm

The Keycloak realm containing the WordPress client and users.

Example:

```text
company
```

### Client ID

The Keycloak OIDC client ID used by WordPress.

Example:

```text
wordpress
```

### Client secret

Required only when the Keycloak client requires client authentication. The value is stored in the WordPress options table, so database access and backups should be protected accordingly.

The plugin does not write client secrets, authorization codes, access tokens, refresh tokens, or ID tokens to its debug log.

### Login mode

Three modes are available:

- **Optional Keycloak login** — the normal WordPress login page remains available and a **Sign in with Keycloak** button is added.
- **Force Keycloak login** — normal interactive visits to the WordPress login form are redirected to Keycloak.
- **Disable interactive Keycloak login** — no Keycloak login button or forced Keycloak login is used.

Force mode intentionally does not intercept WordPress logout, lost-password, reset-password, and post-password actions.

## Emergency Local Login

Before enabling Force mode, keep a tested local administrator account for recovery.

If Keycloak is unavailable or the SSO configuration prevents login, temporarily add this to `wp-config.php`:

```php
define( 'WPKC_ALLOW_LOCAL_LOGIN', true );
```

This bypasses forced Keycloak login and the local-password restriction for Keycloak-linked accounts.

Remove the constant immediately after recovery:

```php
// Remove WPKC_ALLOW_LOCAL_LOGIN after recovery.
```

Do not leave the override permanently enabled on a production site.

## User Provisioning and Account Linking

### Just-in-time provisioning

When **Create users on first login** is enabled, a WordPress user is created the first time an authorized Keycloak identity signs in and no existing link is found.

The plugin stores the identity link using:

```text
wpkc_subject = OIDC sub claim
wpkc_issuer  = Keycloak realm issuer
```

The `sub` + issuer pair is the primary identity link. Email and username are not used as the permanent identity key.

### Initial profile mapping

New users can receive:

| OIDC claim | WordPress field |
|---|---|
| `preferred_username` | `user_login` during account creation |
| `email` | `user_email`, only when `email_verified` is true |
| `given_name` | First name |
| `family_name` | Last name |
| `name` | Display name |

If no usable username exists, the plugin derives one from a verified email address or the Keycloak subject identifier. If the generated username already exists, a numeric suffix is added.

A newly created user initially receives the site's configured **default WordPress role**. Keycloak-mapped roles are then added separately.

For security, keep the WordPress default role non-privileged.

### Linking existing users by email

When **Link existing accounts by verified email** is enabled, the plugin may link a Keycloak identity to an existing WordPress user when:

- the ID token contains an email address;
- `email_verified` is true;
- the WordPress email matches; and
- the WordPress user is not already linked to another Keycloak subject.

Automatic linking to privileged WordPress users is disabled by default.

A user is treated as privileged by this protection when the account can `manage_options` or `promote_users`.

Enable **Allow automatic linking to privileged accounts** only when the Keycloak identity/email lifecycle is controlled strongly enough to justify it.

## Profile Synchronization

When **Synchronize verified profile data on login** is enabled, the plugin updates these fields during successful Keycloak login when the claims are present:

- First name from `given_name`
- Last name from `family_name`
- Display name from `name`
- Email from `email`, only if `email_verified` is true and the address is not owned by another WordPress user

The WordPress username is not changed during later logins.

## Role Mapping

Role mappings are configured one per line.

### Realm roles

```text
realm:wordpress-admin=administrator
realm:content-editor=editor
realm:writer=author
```

### Client roles

Client-role mappings use roles from the configured WordPress Keycloak client:

```text
client:administrator=administrator
client:editor=editor
client:author=author
```

The plugin reads client roles from:

```text
resource_access.<configured-client-id>.roles
```

### Groups

```text
group:/wordpress/admins=administrator
group:/wordpress/editors=editor
group:/writers=author
```

Use the exact group value emitted in the token.

### Comments

Lines beginning with `#` are ignored:

```text
# WordPress administrators
realm:wordpress-admin=administrator
```

### Synchronization behavior

The plugin tracks roles that it has assigned in `wpkc_managed_roles`.

On later interactive Keycloak logins:

- newly matched mapped roles are added;
- mapped roles previously managed by the plugin are removed when the corresponding Keycloak role/group no longer matches;
- WordPress roles not managed by this plugin are preserved.

This means a site's default role or another plugin's role is not automatically removed merely because it is absent from Keycloak.

Only mappings to WordPress roles that currently exist are applied.

## Restricting Who May Sign In

The **Required Keycloak role/group** setting can restrict access to users who possess at least one specified Keycloak source identifier.

Examples:

```text
realm:wordpress-access
```

or:

```text
realm:wordpress-access
client:editor
group:/wordpress/users
```

Comma-separated values are also accepted:

```text
realm:wordpress-access, group:/wordpress/users
```

The rule uses **OR** semantics: access is allowed when any configured item matches.

If the field is empty, no role/group access restriction is applied.

The same access rule is enforced for interactive Keycloak login and Keycloak REST bearer authentication.

## Local WordPress Passwords

When **Disable WordPress password login/reset for linked Keycloak users** is enabled:

- WordPress password authentication is rejected for users that have a `wpkc_subject` link;
- WordPress password reset is disabled for those linked users.

This does not delete the WordPress password hash. It prevents the normal WordPress authentication/reset paths from being used while the setting is enabled.

The emergency `WPKC_ALLOW_LOCAL_LOGIN` constant overrides this restriction.

## OIDC Login Flow

The interactive flow is:

```text
WordPress login
    ↓
Generate state + nonce + PKCE verifier
    ↓
Store short-lived server-side transaction
    ↓
Bind transaction to browser using an HttpOnly SameSite=Lax cookie
    ↓
Redirect to Keycloak authorization endpoint
    ↓
Keycloak authenticates user
    ↓
WordPress callback receives authorization code
    ↓
Validate state + browser binding
    ↓
Exchange code using PKCE verifier
    ↓
Validate signed ID token
    ↓
Validate issuer + audience + nonce + time claims
    ↓
Apply access rules
    ↓
Find/link/create WordPress user
    ↓
Synchronize profile + mapped roles
    ↓
Create WordPress login session
```

Login transactions expire after approximately 10 minutes.

## Discovery and Signing Keys

The plugin uses the standard realm discovery URL:

```text
<issuer>/.well-known/openid-configuration
```

It verifies that the discovery document's `issuer` exactly matches the configured issuer.

The discovery document and JWKS are cached for one hour.

When JWT verification fails because the referenced signing key is not in the cached JWKS, the plugin immediately refreshes JWKS once and retries. This allows Keycloak signing-key rotation without requiring manual cache clearing.

## JWT Validation

The built-in JWT verifier accepts RSA-signed JWTs using:

- `RS256`
- `RS384`
- `RS512`

It validates relevant claims including:

- signature
- `iss`
- `aud`
- `exp`
- `nbf` when present
- `iat` when present
- `nonce` for interactive OIDC login
- `azp` for applicable multi-audience validation

A default clock leeway of 60 seconds is used.

Other signing algorithms such as EC/ES algorithms are not supported by version 1.0.0.

## Logout

### WordPress-initiated logout

When **Redirect WordPress logout through Keycloak** is enabled and Keycloak discovery exposes an `end_session_endpoint`, WordPress logout redirects the user through Keycloak and requests a return to the WordPress logout destination.

The plugin intentionally does not persist ID tokens solely for logout.

### Backchannel logout

Backchannel logout endpoint:

```text
/wp-json/wpkc/v1/backchannel-logout
```

Use the exact full URL shown on **Settings → Keycloak**, especially when WordPress is installed in a subdirectory or uses a nonstandard REST URL.

The endpoint itself does not require a WordPress login because Keycloak must be able to call it server-to-server. Instead, the submitted `logout_token` is cryptographically validated.

The plugin validates the logout token's signature, issuer, audience, expiry, logout event, `jti`, `iat`, absence of `nonce`, and presence of `sub` or `sid`. Used `jti` values are temporarily cached to make duplicate/replayed logout events idempotent.

When a valid logout token matches a WordPress user by Keycloak subject or stored Keycloak session ID, **all WordPress sessions for that matched user are destroyed**. This is deliberately conservative and may sign the user out of multiple browsers/devices on the WordPress site.

## WordPress REST API Bearer Authentication

Enable **Keycloak bearer tokens for WordPress REST API** to allow an already-linked WordPress user to authenticate a REST request with a Keycloak JWT:

```http
Authorization: Bearer <keycloak-jwt>
```

Example request:

```bash
curl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://wordpress.example.com/wp-json/wp/v2/users/me
```

### Important behavior

REST bearer authentication **does not create or automatically link users**.

The token must resolve to an existing WordPress account already linked by the same Keycloak issuer + `sub` identity. Normally the user should sign in interactively through Keycloak at least once before using bearer authentication.

The plugin sets that linked user as the current WordPress user. Normal WordPress REST permission/capability checks still apply after authentication.

### REST audience

The configured **REST token audience** is required to appear in the token's `aud` claim.

If the field is empty, the plugin uses the configured Keycloak **Client ID** as the expected audience.

Keycloak access tokens do not necessarily contain the WordPress client ID as an audience by default. If needed, configure a Keycloak Audience mapper/client scope so the expected audience is emitted in access tokens, or set **REST token audience** to the audience intentionally issued for this integration.

The token must also be issued by the configured Keycloak realm.

For multi-audience tokens, the plugin validates the authorized-party (`azp`) claim against the configured client ID.

### Web-server authorization header forwarding

The plugin checks both:

```text
HTTP_AUTHORIZATION
REDIRECT_HTTP_AUTHORIZATION
```

If bearer authentication does not activate behind a reverse proxy, FastCGI configuration, Apache configuration, or another web server layer, verify that the `Authorization` header is being forwarded to PHP.

## Health / Connection Endpoint

Administrator-only health endpoint:

```text
/wp-json/wpkc/v1/health
```

The **Connection test** link under **Settings → Keycloak** opens this endpoint with a WordPress REST nonce.

The health check forces fresh discovery and JWKS requests and reports information including:

- discovered issuer
- authorization endpoint
- token endpoint
- number of JWKS signing keys
- OIDC callback URL
- backchannel logout URL

Access requires a logged-in WordPress user with the `manage_options` capability.

## WordPress Multisite

When a successfully linked/provisioned Keycloak user signs into a Multisite site and is not already a member of that site, the plugin adds the user to the current site using that site's default role before role mapping is applied.

Review the default role and role mappings carefully on every site in a Multisite network.

Plugin settings are stored using the normal site option and are therefore site-specific unless your deployment manages them externally.

## Security Notes

### Production recommendations

- Use HTTPS for WordPress and Keycloak.
- Use an exact Keycloak base URL and realm.
- Use the narrowest possible valid redirect URIs in Keycloak.
- Keep WordPress's default role non-privileged.
- Do not automatically link privileged WordPress accounts unless required and understood.
- Configure explicit access rules when only a subset of Keycloak users should enter WordPress.
- Test role removal as well as role assignment.
- Keep a separate tested break-glass administrator before enabling Force mode.
- Protect the WordPress database and backups because the client secret is stored in WordPress options when used.
- Ensure WordPress and Keycloak server clocks are synchronized.
- Restrict Keycloak token lifetimes and client permissions according to your security requirements.
- Do not expose `WPKC_ALLOW_LOCAL_LOGIN` permanently.

### Token storage

WP Keycloak Bridge does **not** persist Keycloak access tokens, refresh tokens, or ID tokens after authentication.

The plugin stores identity/session metadata needed for integration, including the Keycloak subject, issuer, mapped-role bookkeeping, last-login timestamp, and current Keycloak session ID when available.

### Login CSRF protection

OIDC `state` is stored server-side in a short-lived WordPress transient and is additionally bound to the initiating browser using a random HttpOnly, `SameSite=Lax` cookie. A callback must satisfy both checks before an authorization code is accepted.

### Redirect protection

The plugin validates WordPress return URLs before redirecting users after login. The configured Keycloak host is explicitly allowed for WordPress's safe redirect handling during Keycloak logout.

## Data Stored by the Plugin

### WordPress option

```text
wpkc_settings
```

This contains the plugin configuration, including the client secret when one is configured.

### User metadata

Depending on enabled features and authentication history, the plugin may store:

```text
wpkc_subject
wpkc_issuer
wpkc_managed_roles
wpkc_last_login
wpkc_sid
```

### Transients

Temporary/cached data includes OIDC login transactions, discovery metadata, JWKS data, and backchannel-logout replay markers.

## Uninstall Behavior

Uninstall is intentionally non-destructive.

Removing the plugin does **not** automatically delete its configuration or user metadata. This prevents accidental identity-link and configuration loss if the plugin is removed temporarily.

If permanent data removal is required, back up the site first and remove the relevant WordPress option/user metadata deliberately.

## Troubleshooting

### “Keycloak is not configured”

Confirm that all of these are populated under **Settings → Keycloak**:

- Keycloak URL
- Realm
- Client ID

### Discovery fails

Check:

- the Keycloak URL does not already include `/realms/<realm>`;
- the realm name is correct;
- WordPress can make outbound HTTPS requests to Keycloak;
- DNS/TLS certificates are valid from the WordPress server;
- the discovery issuer exactly matches the configured Keycloak URL + realm.

### Redirect URI error in Keycloak

Copy the exact **OIDC callback URL** from **Settings → Keycloak** and configure it as a valid redirect URI on the Keycloak client.

Do not guess the callback path when WordPress is installed in a subdirectory or behind a proxy.

### Login succeeds in Keycloak but WordPress denies access

If **Required Keycloak role/group** is configured, confirm that the ID token actually contains one of the required values.

Also verify that any group mapper is emitting the expected full group path/value.

### Role mappings do not apply

Confirm that:

1. The required role/group claim exists in the **ID token**.
2. The mapping prefix is correct: `realm:`, `client:`, or `group:`.
3. The target WordPress role exists.
4. Client roles are defined for the same client ID configured in WordPress.
5. The source value exactly matches the token value.

### Existing administrator cannot be linked automatically

This is expected by default. Automatic email linking to users with `manage_options` or `promote_users` is blocked unless **Allow automatic linking to privileged accounts** is enabled.

### Existing user email causes provisioning failure

If a verified email already belongs to a WordPress account but verified-email linking is disabled or cannot be performed safely, the plugin refuses to create a second account with the same email.

### REST bearer token returns 401

Check:

- REST bearer authentication is enabled;
- the token is issued by the configured realm;
- the token has not expired;
- the expected audience appears in `aud`;
- the user has already been linked to WordPress;
- the web server forwards the `Authorization` header;
- the JWT is signed with an RSA algorithm supported by the plugin.

### REST bearer token returns 403

The token was authenticated but did not satisfy the configured **Required Keycloak role/group** access rule.

### Keycloak logout does not return to WordPress

Check the Keycloak client's allowed post-logout redirect URI configuration and make sure the intended WordPress logout destination is permitted.

### Backchannel logout returns an error

Confirm that Keycloak is sending the logout request to the exact URL shown by WordPress and that the client/realm match the plugin configuration.

The endpoint expects a valid OIDC `logout_token` signed by the configured realm.

### Locked out after enabling Force mode

Temporarily add:

```php
define( 'WPKC_ALLOW_LOCAL_LOGIN', true );
```

to `wp-config.php`, use a local administrator account to repair the configuration, then remove the constant.

## Project Structure

```text
wp-keycloak-bridge/
├── wp-keycloak-bridge.php
├── uninstall.php
├── readme.txt
└── includes/
    ├── class-wpkc-client.php
    ├── class-wpkc-jwt.php
    ├── class-wpkc-plugin.php
    └── class-wpkc-users.php
```

### Main responsibilities

- `wp-keycloak-bridge.php` — plugin bootstrap and activation hook
- `class-wpkc-plugin.php` — WordPress hooks, login flow, settings, logout, REST routes, diagnostics
- `class-wpkc-client.php` — Keycloak issuer, discovery, JWKS, authorization URL, token exchange
- `class-wpkc-jwt.php` — RSA JWT parsing, signature verification, and claim validation
- `class-wpkc-users.php` — identity linking, JIT provisioning, profile sync, access rules, role mapping
- `uninstall.php` — intentionally retains configuration/data

## Current Limitations

Version 1.0.0 intentionally keeps the implementation focused. In particular:

- Only RSA JWT algorithms `RS256`, `RS384`, and `RS512` are accepted.
- Interactive authentication uses ID-token claims; there is no UserInfo request.
- There is no refresh-token workflow.
- Keycloak tokens are not persisted.
- REST bearer authentication requires an already-linked WordPress user and does not perform JIT provisioning.
- Role/group synchronization is performed during interactive Keycloak login, not continuously in the background.
- Backchannel logout destroys all WordPress sessions for a matched user rather than only a single WordPress session.
- There is no Keycloak Admin REST API provisioning or bidirectional user administration.
- There is no SAML support.
- There is no built-in UI for manually linking/unlinking individual WordPress users.
- Uninstall does not delete plugin configuration or identity metadata.

## Version

Current release documented here: **1.0.0**

## License

GPL-2.0-or-later.
