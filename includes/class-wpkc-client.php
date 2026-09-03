<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WPKC_Client {
    private array $settings;
    public function __construct( array $settings ) { $this->settings = $settings; }

    public function issuer(): string {
        $base = untrailingslashit( trim( (string) ( $this->settings['keycloak_url'] ?? '' ) ) );
        $realm = rawurlencode( trim( (string) ( $this->settings['realm'] ?? '' ) ) );
        return $base && $realm ? $base . '/realms/' . $realm : '';
    }
    public function callback_url(): string { return admin_url( 'admin-post.php?action=wpkc_callback' ); }

    public function discovery( bool $force = false ) {
        $issuer = $this->issuer();
        if ( ! $issuer ) { return new WP_Error( 'wpkc_config', __( 'Keycloak URL and realm are required.', 'wp-keycloak-bridge' ) ); }
        $key = 'wpkc_disc_' . md5( $issuer );
        if ( ! $force ) { $cached = get_transient( $key ); if ( is_array( $cached ) ) { return $cached; } }
        $response = wp_safe_remote_get( $issuer . '/.well-known/openid-configuration', array( 'timeout' => 10, 'redirection' => 3 ) );
        if ( is_wp_error( $response ) ) { return $response; }
        if ( 200 !== wp_remote_retrieve_response_code( $response ) ) { return new WP_Error( 'wpkc_discovery_http', __( 'Keycloak discovery request failed.', 'wp-keycloak-bridge' ) ); }
        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) || empty( $data['issuer'] ) || ! hash_equals( $issuer, untrailingslashit( (string) $data['issuer'] ) ) ) {
            return new WP_Error( 'wpkc_discovery_issuer', __( 'Keycloak discovery issuer does not match configuration.', 'wp-keycloak-bridge' ) );
        }
        foreach ( array( 'authorization_endpoint', 'token_endpoint', 'jwks_uri' ) as $required ) {
            if ( empty( $data[ $required ] ) || ! wp_http_validate_url( $data[ $required ] ) ) {
                return new WP_Error( 'wpkc_discovery_missing', sprintf( __( 'Discovery is missing a valid %s.', 'wp-keycloak-bridge' ), $required ) );
            }
        }
        set_transient( $key, $data, HOUR_IN_SECONDS );
        return $data;
    }

    public function jwks( bool $force = false ) {
        $d = $this->discovery( $force ); if ( is_wp_error( $d ) ) { return $d; }
        $key = 'wpkc_jwks_' . md5( (string) $d['jwks_uri'] );
        if ( ! $force ) { $cached = get_transient( $key ); if ( is_array( $cached ) ) { return $cached; } }
        $r = wp_safe_remote_get( $d['jwks_uri'], array( 'timeout' => 10, 'redirection' => 2 ) );
        if ( is_wp_error( $r ) ) { return $r; }
        if ( 200 !== wp_remote_retrieve_response_code( $r ) ) { return new WP_Error( 'wpkc_jwks_http', __( 'Unable to retrieve Keycloak signing keys.', 'wp-keycloak-bridge' ) ); }
        $keys = json_decode( wp_remote_retrieve_body( $r ), true );
        if ( ! is_array( $keys ) || empty( $keys['keys'] ) ) { return new WP_Error( 'wpkc_jwks_invalid', __( 'Invalid JWKS response.', 'wp-keycloak-bridge' ) ); }
        set_transient( $key, $keys, HOUR_IN_SECONDS );
        return $keys;
    }

    public function validate_jwt( string $jwt, array $expected = array() ) {
        $expected['issuer'] = $this->issuer();
        $jwks = $this->jwks(); if ( is_wp_error( $jwks ) ) { return $jwks; }
        $result = WPKC_JWT::decode_and_verify( $jwt, $jwks, $expected );
        if ( is_wp_error( $result ) && 'wpkc_jwk_missing' === $result->get_error_code() ) {
            $jwks = $this->jwks( true ); if ( is_wp_error( $jwks ) ) { return $jwks; }
            $result = WPKC_JWT::decode_and_verify( $jwt, $jwks, $expected );
        }
        return $result;
    }

    public function authorization_url( string $state, string $nonce, string $challenge ): string {
        $d = $this->discovery(); if ( is_wp_error( $d ) ) { return ''; }
        return add_query_arg( array(
            'client_id' => (string) $this->settings['client_id'], 'response_type' => 'code',
            'scope' => 'openid profile email', 'redirect_uri' => $this->callback_url(), 'state' => $state,
            'nonce' => $nonce, 'code_challenge' => $challenge, 'code_challenge_method' => 'S256',
        ), $d['authorization_endpoint'] );
    }

    public function exchange_code( string $code, string $verifier ) {
        $d = $this->discovery(); if ( is_wp_error( $d ) ) { return $d; }
        $body = array( 'grant_type' => 'authorization_code', 'client_id' => (string) $this->settings['client_id'],
            'code' => $code, 'redirect_uri' => $this->callback_url(), 'code_verifier' => $verifier );
        $secret = (string) ( $this->settings['client_secret'] ?? '' );
        if ( '' !== $secret ) { $body['client_secret'] = $secret; }
        $r = wp_safe_remote_post( $d['token_endpoint'], array( 'timeout' => 12, 'redirection' => 0, 'body' => $body ) );
        if ( is_wp_error( $r ) ) { return $r; }
        $data = json_decode( wp_remote_retrieve_body( $r ), true );
        if ( 200 !== wp_remote_retrieve_response_code( $r ) || ! is_array( $data ) || empty( $data['id_token'] ) ) {
            return new WP_Error( 'wpkc_token_exchange', __( 'Keycloak token exchange failed.', 'wp-keycloak-bridge' ) );
        }
        return $data;
    }
}
