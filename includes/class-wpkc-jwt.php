<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WPKC_JWT {
    private const ALGS = array(
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
    );

    public static function decode_and_verify( string $jwt, array $jwks, array $expected = array() ) {
        $parts = explode( '.', $jwt );
        if ( 3 !== count( $parts ) ) {
            return new WP_Error( 'wpkc_jwt_format', __( 'Malformed JWT.', 'wp-keycloak-bridge' ) );
        }
        $header  = self::json_part( $parts[0] );
        $payload = self::json_part( $parts[1] );
        $sig     = self::b64url_decode( $parts[2] );
        if ( is_wp_error( $header ) || is_wp_error( $payload ) || false === $sig ) {
            return new WP_Error( 'wpkc_jwt_decode', __( 'Unable to decode JWT.', 'wp-keycloak-bridge' ) );
        }
        $alg = isset( $header['alg'] ) ? (string) $header['alg'] : '';
        if ( ! isset( self::ALGS[ $alg ] ) ) {
            return new WP_Error( 'wpkc_jwt_alg', __( 'Unsupported JWT signing algorithm.', 'wp-keycloak-bridge' ) );
        }
        $kid = isset( $header['kid'] ) ? (string) $header['kid'] : '';
        $jwk = self::find_jwk( $jwks, $kid, $alg );
        if ( is_wp_error( $jwk ) ) { return $jwk; }
        $pem = self::rsa_jwk_to_pem( $jwk );
        if ( is_wp_error( $pem ) ) { return $pem; }
        $ok = openssl_verify( $parts[0] . '.' . $parts[1], $sig, $pem, self::ALGS[ $alg ] );
        if ( 1 !== $ok ) {
            return new WP_Error( 'wpkc_jwt_signature', __( 'Invalid JWT signature.', 'wp-keycloak-bridge' ) );
        }
        $claims_ok = self::validate_claims( $payload, $expected );
        if ( is_wp_error( $claims_ok ) ) { return $claims_ok; }
        return $payload;
    }

    private static function json_part( string $part ) {
        $raw = self::b64url_decode( $part );
        if ( false === $raw ) { return new WP_Error( 'wpkc_b64', 'Invalid base64url.' ); }
        $data = json_decode( $raw, true );
        return is_array( $data ) ? $data : new WP_Error( 'wpkc_json', 'Invalid JWT JSON.' );
    }

    public static function b64url_decode( string $input ) {
        if ( ! preg_match( '/^[A-Za-z0-9_-]*$/', $input ) ) { return false; }
        $pad = strlen( $input ) % 4;
        if ( $pad ) { $input .= str_repeat( '=', 4 - $pad ); }
        return base64_decode( strtr( $input, '-_', '+/' ), true );
    }

    private static function find_jwk( array $jwks, string $kid, string $alg ) {
        $keys = isset( $jwks['keys'] ) && is_array( $jwks['keys'] ) ? $jwks['keys'] : array();
        foreach ( $keys as $key ) {
            if ( ! is_array( $key ) || ( $key['kty'] ?? '' ) !== 'RSA' ) { continue; }
            if ( $kid !== '' && ( $key['kid'] ?? '' ) !== $kid ) { continue; }
            if ( isset( $key['use'] ) && 'sig' !== $key['use'] ) { continue; }
            if ( isset( $key['alg'] ) && $key['alg'] !== $alg ) { continue; }
            return $key;
        }
        return new WP_Error( 'wpkc_jwk_missing', __( 'No matching Keycloak signing key was found.', 'wp-keycloak-bridge' ) );
    }

    private static function validate_claims( array $claims, array $expected ) {
        $now    = time();
        $leeway = isset( $expected['leeway'] ) ? max( 0, (int) $expected['leeway'] ) : 60;
        if ( ! isset( $claims['exp'] ) || ! is_numeric( $claims['exp'] ) || (int) $claims['exp'] < $now - $leeway ) {
            return new WP_Error( 'wpkc_jwt_expired', __( 'JWT is expired or has no valid expiration.', 'wp-keycloak-bridge' ) );
        }
        if ( isset( $claims['nbf'] ) && is_numeric( $claims['nbf'] ) && (int) $claims['nbf'] > $now + $leeway ) {
            return new WP_Error( 'wpkc_jwt_nbf', __( 'JWT is not valid yet.', 'wp-keycloak-bridge' ) );
        }
        if ( isset( $claims['iat'] ) && is_numeric( $claims['iat'] ) && (int) $claims['iat'] > $now + $leeway ) {
            return new WP_Error( 'wpkc_jwt_iat', __( 'JWT issue time is in the future.', 'wp-keycloak-bridge' ) );
        }
        if ( ! empty( $expected['issuer'] ) && ( ! isset( $claims['iss'] ) || ! hash_equals( (string) $expected['issuer'], (string) $claims['iss'] ) ) ) {
            return new WP_Error( 'wpkc_jwt_issuer', __( 'JWT issuer mismatch.', 'wp-keycloak-bridge' ) );
        }
        if ( ! empty( $expected['audience'] ) ) {
            $aud = $claims['aud'] ?? array();
            $aud = is_array( $aud ) ? array_map( 'strval', $aud ) : array( (string) $aud );
            if ( ! in_array( (string) $expected['audience'], $aud, true ) ) {
                return new WP_Error( 'wpkc_jwt_audience', __( 'JWT audience mismatch.', 'wp-keycloak-bridge' ) );
            }
            if ( count( $aud ) > 1 && isset( $expected['authorized_party'] ) ) {
                if ( ! isset( $claims['azp'] ) || ! hash_equals( (string) $expected['authorized_party'], (string) $claims['azp'] ) ) {
                    return new WP_Error( 'wpkc_jwt_azp', __( 'JWT authorized party mismatch.', 'wp-keycloak-bridge' ) );
                }
            }
        }
        if ( isset( $expected['nonce'] ) && ( ! isset( $claims['nonce'] ) || ! hash_equals( (string) $expected['nonce'], (string) $claims['nonce'] ) ) ) {
            return new WP_Error( 'wpkc_jwt_nonce', __( 'OIDC nonce mismatch.', 'wp-keycloak-bridge' ) );
        }
        if ( isset( $expected['events_uri'] ) ) {
            $events = $claims['events'] ?? array();
            if ( ! is_array( $events ) || ! array_key_exists( $expected['events_uri'], $events ) || ! is_array( $events[ $expected['events_uri'] ] ) ) {
                return new WP_Error( 'wpkc_logout_event', __( 'Invalid logout token event.', 'wp-keycloak-bridge' ) );
            }
            if ( isset( $claims['nonce'] ) ) {
                return new WP_Error( 'wpkc_logout_nonce', __( 'Logout token must not contain a nonce.', 'wp-keycloak-bridge' ) );
            }
        }
        return true;
    }

    private static function rsa_jwk_to_pem( array $jwk ) {
        if ( empty( $jwk['n'] ) || empty( $jwk['e'] ) ) {
            return new WP_Error( 'wpkc_jwk_rsa', __( 'Invalid RSA JWK.', 'wp-keycloak-bridge' ) );
        }
        $n = self::b64url_decode( (string) $jwk['n'] );
        $e = self::b64url_decode( (string) $jwk['e'] );
        if ( false === $n || false === $e ) { return new WP_Error( 'wpkc_jwk_b64', 'Invalid JWK encoding.' ); }
        $rsa = self::asn1_sequence( self::asn1_integer( $n ) . self::asn1_integer( $e ) );
        $alg = hex2bin( '300d06092a864886f70d0101010500' );
        $bit = "\x03" . self::asn1_length( strlen( $rsa ) + 1 ) . "\x00" . $rsa;
        $der = self::asn1_sequence( $alg . $bit );
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
    }

    private static function asn1_integer( string $bytes ): string {
        $bytes = ltrim( $bytes, "\x00" );
        if ( '' === $bytes ) { $bytes = "\x00"; }
        if ( ord( $bytes[0] ) > 0x7f ) { $bytes = "\x00" . $bytes; }
        return "\x02" . self::asn1_length( strlen( $bytes ) ) . $bytes;
    }
    private static function asn1_sequence( string $bytes ): string { return "\x30" . self::asn1_length( strlen( $bytes ) ) . $bytes; }
    private static function asn1_length( int $length ): string {
        if ( $length <= 0x7f ) { return chr( $length ); }
        $temp = '';
        while ( $length > 0 ) { $temp = chr( $length & 0xff ) . $temp; $length >>= 8; }
        return chr( 0x80 | strlen( $temp ) ) . $temp;
    }
}
