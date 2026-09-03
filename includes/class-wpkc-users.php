<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WPKC_Users {
    private array $settings;
    public function __construct( array $settings ) { $this->settings = $settings; }

    public function find_or_create( array $claims, string $issuer ) {
        if ( empty( $claims['sub'] ) ) { return new WP_Error( 'wpkc_no_sub', __( 'Keycloak identity has no subject identifier.', 'wp-keycloak-bridge' ) ); }
        $users = get_users( array( 'number' => 2, 'meta_query' => array( 'relation' => 'AND',
            array( 'key' => 'wpkc_subject', 'value' => (string) $claims['sub'] ),
            array( 'key' => 'wpkc_issuer', 'value' => $issuer ),
        ) ) );
        if ( count( $users ) > 1 ) { return new WP_Error( 'wpkc_duplicate_subject', __( 'Multiple WordPress users are linked to this Keycloak identity.', 'wp-keycloak-bridge' ) ); }
        $user = $users ? $users[0] : null;

        if ( ! $user ) {
            $email = isset( $claims['email'] ) ? sanitize_email( (string) $claims['email'] ) : '';
            $verified = ! empty( $claims['email_verified'] );
            if ( $email && $verified && ! empty( $this->settings['link_verified_email'] ) ) {
                $candidate = get_user_by( 'email', $email );
                if ( $candidate ) {
                    $already = get_user_meta( $candidate->ID, 'wpkc_subject', true );
                    if ( $already ) { return new WP_Error( 'wpkc_email_linked', __( 'That email address is already linked to another Keycloak identity.', 'wp-keycloak-bridge' ) ); }
                    if ( $this->is_privileged( $candidate ) && empty( $this->settings['link_privileged_email'] ) ) {
                        return new WP_Error( 'wpkc_privileged_link', __( 'Automatic linking to a privileged WordPress account is disabled.', 'wp-keycloak-bridge' ) );
                    }
                    $user = $candidate;
                }
            }
            if ( ! $user ) {
                $user = $this->create_user( $claims );
                if ( is_wp_error( $user ) ) { return $user; }
            }
            update_user_meta( $user->ID, 'wpkc_subject', (string) $claims['sub'] );
            update_user_meta( $user->ID, 'wpkc_issuer', $issuer );
        }
        if ( is_multisite() && ! is_user_member_of_blog( $user->ID, get_current_blog_id() ) ) {
            add_user_to_blog( get_current_blog_id(), $user->ID, get_option( 'default_role', 'subscriber' ) );
        }
        $this->sync_profile( $user, $claims );
        $this->sync_roles( $user, $claims );
        update_user_meta( $user->ID, 'wpkc_last_login', time() );
        return get_user_by( 'id', $user->ID );
    }

    public function find_by_claims( array $claims, string $issuer ) {
        if ( empty( $claims['sub'] ) ) { return false; }
        $users = get_users( array( 'number' => 1, 'meta_query' => array( 'relation' => 'AND',
            array( 'key' => 'wpkc_subject', 'value' => (string) $claims['sub'] ), array( 'key' => 'wpkc_issuer', 'value' => $issuer ) ) ) );
        return $users ? $users[0] : false;
    }

    private function create_user( array $claims ) {
        if ( empty( $this->settings['jit_provisioning'] ) ) { return new WP_Error( 'wpkc_jit_disabled', __( 'Automatic user provisioning is disabled.', 'wp-keycloak-bridge' ) ); }
        $email = ! empty( $claims['email_verified'] ) && isset( $claims['email'] ) ? sanitize_email( (string) $claims['email'] ) : '';
        if ( $email && email_exists( $email ) ) { return new WP_Error( 'wpkc_email_exists', __( 'A WordPress account with this email already exists and cannot be linked automatically.', 'wp-keycloak-bridge' ) ); }
        $base = sanitize_user( (string) ( $claims['preferred_username'] ?? '' ), true );
        if ( '' === $base && $email ) { $base = sanitize_user( strstr( $email, '@', true ), true ); }
        if ( '' === $base ) { $base = 'keycloak_' . substr( preg_replace( '/[^a-zA-Z0-9]/', '', (string) $claims['sub'] ), 0, 12 ); }
        $login = $base; $i = 1;
        while ( username_exists( $login ) ) { $login = $base . '_' . $i++; if ( $i > 1000 ) { return new WP_Error( 'wpkc_username', 'Unable to allocate username.' ); } }
        $id = wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password( 64, true, true ), 'user_email' => $email,
            'first_name' => sanitize_text_field( (string) ( $claims['given_name'] ?? '' ) ), 'last_name' => sanitize_text_field( (string) ( $claims['family_name'] ?? '' ) ),
            'display_name' => sanitize_text_field( (string) ( $claims['name'] ?? $login ) ), 'role' => get_option( 'default_role', 'subscriber' ) ) );
        return is_wp_error( $id ) ? $id : get_user_by( 'id', $id );
    }

    private function sync_profile( WP_User $user, array $claims ): void {
        if ( empty( $this->settings['sync_profile'] ) ) { return; }
        $data = array( 'ID' => $user->ID );
        if ( isset( $claims['given_name'] ) ) { $data['first_name'] = sanitize_text_field( (string) $claims['given_name'] ); }
        if ( isset( $claims['family_name'] ) ) { $data['last_name'] = sanitize_text_field( (string) $claims['family_name'] ); }
        if ( isset( $claims['name'] ) ) { $data['display_name'] = sanitize_text_field( (string) $claims['name'] ); }
        if ( ! empty( $claims['email'] ) && ! empty( $claims['email_verified'] ) ) {
            $email = sanitize_email( (string) $claims['email'] );
            $owner = $email ? email_exists( $email ) : false;
            if ( $email && ( ! $owner || (int) $owner === (int) $user->ID ) ) { $data['user_email'] = $email; }
        }
        if ( count( $data ) > 1 ) { wp_update_user( $data ); }
    }

    private function sync_roles( WP_User $user, array $claims ): void {
        $map = $this->role_map();
        if ( ! $map ) { return; }
        $kc_roles = $this->claim_roles( $claims );
        $desired = array();
        foreach ( $map as $source => $wp_role ) { if ( in_array( $source, $kc_roles, true ) && get_role( $wp_role ) ) { $desired[] = $wp_role; } }
        $desired = array_values( array_unique( $desired ) );
        $managed = get_user_meta( $user->ID, 'wpkc_managed_roles', true );
        $managed = is_array( $managed ) ? $managed : array();
        foreach ( $managed as $role ) { if ( ! in_array( $role, $desired, true ) && in_array( $role, $user->roles, true ) ) { $user->remove_role( $role ); } }
        foreach ( $desired as $role ) { if ( ! in_array( $role, $user->roles, true ) ) { $user->add_role( $role ); } }
        update_user_meta( $user->ID, 'wpkc_managed_roles', $desired );
    }

    public function claim_roles( array $claims ): array {
        $roles = array();
        foreach ( (array) ( $claims['realm_access']['roles'] ?? array() ) as $r ) { $roles[] = 'realm:' . (string) $r; }
        $client = (string) ( $this->settings['client_id'] ?? '' );
        foreach ( (array) ( $claims['resource_access'][ $client ]['roles'] ?? array() ) as $r ) { $roles[] = 'client:' . (string) $r; }
        foreach ( (array) ( $claims['groups'] ?? array() ) as $g ) { $roles[] = 'group:' . (string) $g; }
        return array_values( array_unique( $roles ) );
    }

    public function passes_access_rule( array $claims ): bool {
        $required = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', (string) ( $this->settings['required_access'] ?? '' ) ) ) );
        return ! $required || (bool) array_intersect( $required, $this->claim_roles( $claims ) );
    }

    private function role_map(): array {
        $map = array();
        foreach ( preg_split( '/\r\n|\r|\n/', (string) ( $this->settings['role_map'] ?? '' ) ) as $line ) {
            $line = trim( $line ); if ( '' === $line || str_starts_with( $line, '#' ) || ! str_contains( $line, '=' ) ) { continue; }
            list( $a, $b ) = array_map( 'trim', explode( '=', $line, 2 ) );
            if ( $a && $b ) { $map[ $a ] = sanitize_key( $b ); }
        }
        return $map;
    }

    private function is_privileged( WP_User $user ): bool { return user_can( $user, 'manage_options' ) || user_can( $user, 'promote_users' ); }
}
