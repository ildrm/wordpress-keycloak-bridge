<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WPKC_Plugin {
    private static ?self $instance = null;
    private array $settings;
    private WPKC_Client $client;
    private WPKC_Users $users;

    public static function instance(): self { return self::$instance ??= new self(); }
    public static function activate(): void { if ( false === get_option( 'wpkc_settings', false ) ) { add_option( 'wpkc_settings', self::defaults(), '', false ); } }
    private static function defaults(): array { return array( 'keycloak_url'=>'','realm'=>'','client_id'=>'','client_secret'=>'','login_mode'=>'optional','jit_provisioning'=>1,'sync_profile'=>1,'link_verified_email'=>1,'link_privileged_email'=>0,'disable_local_for_linked'=>1,'role_map'=>'','required_access'=>'','rest_bearer'=>0,'rest_audience'=>'','logout_keycloak'=>1,'debug'=>0 ); }

    private function __construct() {
        $this->settings = wp_parse_args( get_option( 'wpkc_settings', array() ), self::defaults() );
        $this->client = new WPKC_Client( $this->settings ); $this->users = new WPKC_Users( $this->settings );
        add_action( 'login_form_wpkc_login', array( $this, 'start_login' ) );
        add_action( 'admin_post_nopriv_wpkc_callback', array( $this, 'callback' ) ); add_action( 'admin_post_wpkc_callback', array( $this, 'callback' ) );
        add_filter( 'login_message', array( $this, 'login_message' ) ); add_action( 'login_init', array( $this, 'maybe_force_login' ) );
        add_filter( 'authenticate', array( $this, 'block_local_auth_for_linked' ), 50, 3 ); add_filter( 'allow_password_reset', array( $this, 'block_password_reset_for_linked' ), 10, 2 );
        add_filter( 'logout_redirect', array( $this, 'logout_redirect' ), 10, 3 ); add_filter( 'allowed_redirect_hosts', array( $this, 'allowed_redirect_hosts' ) );
        add_action( 'rest_api_init', array( $this, 'register_rest' ) ); add_filter( 'rest_authentication_errors', array( $this, 'rest_bearer_auth' ), 20 );
        add_action( 'admin_menu', array( $this, 'admin_menu' ) ); add_action( 'admin_init', array( $this, 'admin_init' ) );
        add_filter( 'plugin_action_links_' . plugin_basename( WPKC_FILE ), array( $this, 'plugin_links' ) );
    }

    private function configured(): bool { return (bool) ( $this->settings['keycloak_url'] && $this->settings['realm'] && $this->settings['client_id'] ); }
    private function login_url( string $redirect = '' ): string { return add_query_arg( array( 'action'=>'wpkc_login','redirect_to'=>$redirect ?: admin_url() ), wp_login_url() ); }

    public function login_message( string $message ): string {
        if ( ! $this->configured() || 'disabled' === $this->settings['login_mode'] ) { return $message; }
        $url = esc_url( $this->login_url( isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : '' ) );
        return $message . '<p class="message" style="text-align:center"><a class="button button-primary button-large" href="' . $url . '">' . esc_html__( 'Sign in with Keycloak', 'wp-keycloak-bridge' ) . '</a></p>';
    }

    public function maybe_force_login(): void {
        if ( ! $this->configured() || 'force' !== $this->settings['login_mode'] ) { return; }
        $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
        if ( in_array( $action, array( 'wpkc_login','logout','lostpassword','rp','resetpass','postpass' ), true ) ) { return; }
        if ( defined( 'WPKC_ALLOW_LOCAL_LOGIN' ) && WPKC_ALLOW_LOCAL_LOGIN ) { return; }
        if ( ! is_user_logged_in() ) { wp_safe_redirect( $this->login_url( isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url() ) ); exit; }
    }


    public function block_local_auth_for_linked( $user, $username, $password ) {
        if ( empty( $this->settings['disable_local_for_linked'] ) || ( defined( 'WPKC_ALLOW_LOCAL_LOGIN' ) && WPKC_ALLOW_LOCAL_LOGIN ) || ! ( $user instanceof WP_User ) ) { return $user; }
        if ( get_user_meta( $user->ID, 'wpkc_subject', true ) ) {
            return new WP_Error( 'wpkc_local_disabled', __( 'This account is managed by Keycloak. Use “Sign in with Keycloak”.', 'wp-keycloak-bridge' ) );
        }
        return $user;
    }

    public function block_password_reset_for_linked( $allow, int $user_id ) {
        if ( empty( $this->settings['disable_local_for_linked'] ) || ( defined( 'WPKC_ALLOW_LOCAL_LOGIN' ) && WPKC_ALLOW_LOCAL_LOGIN ) ) { return $allow; }
        return get_user_meta( $user_id, 'wpkc_subject', true ) ? false : $allow;
    }

    public function start_login(): void {
        if ( ! $this->configured() ) { wp_die( esc_html__( 'Keycloak is not configured.', 'wp-keycloak-bridge' ), esc_html__( 'Keycloak configuration error', 'wp-keycloak-bridge' ), array( 'response' => 400 ) ); }
        $state = bin2hex( random_bytes( 24 ) ); $nonce = bin2hex( random_bytes( 24 ) );
        $verifier = rtrim( strtr( base64_encode( random_bytes( 48 ) ), '+/', '-_' ), '=' );
        $challenge = rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
        $cookie = bin2hex( random_bytes( 24 ) );
        $redirect = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), admin_url() ) : admin_url();
        set_transient( 'wpkc_state_' . hash( 'sha256', $state ), array( 'nonce'=>$nonce,'verifier'=>$verifier,'cookie_hash'=>hash( 'sha256', $cookie ),'redirect'=>$redirect ), 10 * MINUTE_IN_SECONDS );
        $this->set_state_cookie( $cookie, time() + 600 );
        $url = $this->client->authorization_url( $state, $nonce, $challenge );
        if ( ! $url ) { wp_die( esc_html__( 'Unable to discover Keycloak authorization endpoint.', 'wp-keycloak-bridge' ), esc_html__( 'Keycloak connection error', 'wp-keycloak-bridge' ), array( 'response' => 502 ) ); }
        wp_redirect( esc_url_raw( $url ) ); exit;
    }

    public function callback(): void {
        if ( isset( $_GET['error'] ) && is_string( $_GET['error'] ) ) {
            $error = sanitize_key( wp_unslash( $_GET['error'] ) );
            $description = isset( $_GET['error_description'] ) && is_string( $_GET['error_description'] ) ? sanitize_text_field( wp_unslash( $_GET['error_description'] ) ) : '';
            $this->fail( 'Keycloak returned an authorization error: ' . $error . ( $description ? ' — ' . $description : '' ) );
        }
        $state = isset( $_GET['state'] ) && is_string( $_GET['state'] ) ? wp_unslash( $_GET['state'] ) : '';
        $code = isset( $_GET['code'] ) && is_string( $_GET['code'] ) ? wp_unslash( $_GET['code'] ) : '';
        if ( ! preg_match( '/^[A-Za-z0-9._~-]{20,512}$/', $state ) || '' === $code || strlen( $code ) > 4096 ) { $this->fail( 'Missing or invalid OIDC state/authorization code.' ); }
        $key = 'wpkc_state_' . hash( 'sha256', $state ); $tx = get_transient( $key ); delete_transient( $key );
        if ( ! is_array( $tx ) || empty( $_COOKIE['wpkc_state'] ) || ! hash_equals( (string) $tx['cookie_hash'], hash( 'sha256', (string) $_COOKIE['wpkc_state'] ) ) ) { $this->fail( 'Invalid or expired OIDC transaction.' ); }
        $this->set_state_cookie( '', time() - 3600 );
        $tokens = $this->client->exchange_code( $code, (string) $tx['verifier'] ); if ( is_wp_error( $tokens ) ) { $this->fail( $tokens->get_error_message() ); }
        $claims = $this->client->validate_jwt( (string) $tokens['id_token'], array( 'audience'=>(string)$this->settings['client_id'],'authorized_party'=>(string)$this->settings['client_id'],'nonce'=>(string)$tx['nonce'] ) );
        if ( is_wp_error( $claims ) ) { $this->fail( $claims->get_error_message() ); }
        if ( ! $this->users->passes_access_rule( $claims ) ) { $this->fail( 'Your Keycloak account is not authorized for this WordPress site.', 403 ); }
        $user = $this->users->find_or_create( $claims, $this->client->issuer() ); if ( is_wp_error( $user ) ) { $this->fail( $user->get_error_message() ); }
        wp_clear_auth_cookie(); wp_set_current_user( $user->ID ); wp_set_auth_cookie( $user->ID, false, is_ssl() ); do_action( 'wp_login', $user->user_login, $user );
        if ( ! empty( $claims['sid'] ) ) { update_user_meta( $user->ID, 'wpkc_sid', sanitize_text_field( (string) $claims['sid'] ) ); }
        wp_safe_redirect( wp_validate_redirect( (string) $tx['redirect'], admin_url() ) ); exit;
    }

    private function set_state_cookie( string $value, int $expires ): void {
        setcookie( 'wpkc_state', $value, array( 'expires'=>$expires,'path'=>COOKIEPATH ?: '/','domain'=>COOKIE_DOMAIN ?: '','secure'=>is_ssl(),'httponly'=>true,'samesite'=>'Lax' ) );
    }
    private function fail( string $message, int $status = 400 ): void { $this->log( 'Authentication failure: ' . $message ); wp_die( esc_html( $message ), esc_html__( 'Keycloak authentication failed', 'wp-keycloak-bridge' ), array( 'response'=>$status ) ); }

    public function logout_redirect( string $redirect_to, string $requested, WP_User $user ): string {
        if ( empty( $this->settings['logout_keycloak'] ) || ! $this->configured() || ! $user->exists() ) { return $redirect_to; }
        delete_user_meta( $user->ID, 'wpkc_sid' );
        $d = $this->client->discovery(); if ( is_wp_error( $d ) || empty( $d['end_session_endpoint'] ) ) { return $redirect_to; }
        return add_query_arg( array( 'post_logout_redirect_uri'=>wp_validate_redirect( $redirect_to, home_url( '/' ) ), 'client_id'=>(string)$this->settings['client_id'] ), $d['end_session_endpoint'] );
    }


    public function allowed_redirect_hosts( array $hosts ): array {
        if ( ! $this->configured() ) { return $hosts; }
        $host = wp_parse_url( (string) $this->settings['keycloak_url'], PHP_URL_HOST );
        if ( $host && ! in_array( $host, $hosts, true ) ) { $hosts[] = $host; }
        return $hosts;
    }

    public function register_rest(): void {
        register_rest_route( 'wpkc/v1', '/backchannel-logout', array( 'methods'=>'POST','callback'=>array($this,'backchannel_logout'),'permission_callback'=>'__return_true' ) );
        register_rest_route( 'wpkc/v1', '/health', array( 'methods'=>'GET','callback'=>array($this,'health'),'permission_callback'=>function(){ return current_user_can('manage_options'); } ) );
    }
    public function backchannel_logout( WP_REST_Request $request ) {
        $token = (string) $request->get_param( 'logout_token' ); if ( ! $token ) { return new WP_Error( 'wpkc_logout_missing', 'Missing logout_token.', array('status'=>400) ); }
        $claims = $this->client->validate_jwt( $token, array( 'audience'=>(string)$this->settings['client_id'],'events_uri'=>'http://schemas.openid.net/event/backchannel-logout' ) );
        if ( is_wp_error( $claims ) ) { return new WP_Error( $claims->get_error_code(), $claims->get_error_message(), array('status'=>400) ); }
        if ( empty( $claims['jti'] ) || ! isset( $claims['iat'] ) || ! is_numeric( $claims['iat'] ) || ( empty( $claims['sub'] ) && empty( $claims['sid'] ) ) ) {
            return new WP_Error( 'wpkc_logout_claims', 'Logout token is missing required claims.', array('status'=>400) );
        }
        $replay_key = 'wpkc_logout_' . hash( 'sha256', $this->client->issuer() . '|' . (string) $claims['jti'] );
        if ( get_transient( $replay_key ) ) { return new WP_REST_Response( null, 204 ); }
        $ttl = max( 60, min( DAY_IN_SECONDS, (int) $claims['exp'] - time() + 60 ) ); set_transient( $replay_key, 1, $ttl );
        $matched = array();
        if ( ! empty( $claims['sub'] ) ) { $u=$this->users->find_by_claims($claims,$this->client->issuer()); if($u){$matched[$u->ID]=$u;} }
        if ( ! empty( $claims['sid'] ) ) { foreach ( get_users(array('meta_key'=>'wpkc_sid','meta_value'=>sanitize_text_field((string)$claims['sid']))) as $u ) { $matched[$u->ID]=$u; } }
        if ( ! $matched ) { return new WP_REST_Response( null, 204 ); }
        foreach ( $matched as $u ) { WP_Session_Tokens::get_instance( $u->ID )->destroy_all(); delete_user_meta($u->ID,'wpkc_sid'); }
        return new WP_REST_Response( null, 204 );
    }

    public function rest_bearer_auth( $result ) {
        if ( null !== $result || empty( $this->settings['rest_bearer'] ) ) { return $result; }
        $header = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? trim( (string) $_SERVER['HTTP_AUTHORIZATION'] ) : ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? trim( (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) : '' );
        if ( ! preg_match( '/^Bearer\s+(.+)$/i', $header, $m ) ) { return $result; }
        $rest_audience = trim( (string) ( $this->settings['rest_audience'] ?? '' ) ); if ( '' === $rest_audience ) { $rest_audience = (string) $this->settings['client_id']; }
        $claims = $this->client->validate_jwt( trim($m[1]), array( 'audience'=>$rest_audience,'authorized_party'=>(string)$this->settings['client_id'] ) );
        if ( is_wp_error( $claims ) ) { return new WP_Error( 'wpkc_rest_token', $claims->get_error_message(), array('status'=>401) ); }
        if ( ! $this->users->passes_access_rule( $claims ) ) { return new WP_Error( 'wpkc_rest_denied', 'Keycloak account is not authorized.', array('status'=>403) ); }
        $user = $this->users->find_by_claims( $claims, $this->client->issuer() ); if ( ! $user ) { return new WP_Error( 'wpkc_rest_user', 'No linked WordPress user exists for this token.', array('status'=>401) ); }
        wp_set_current_user( $user->ID ); return true;
    }

    public function health() {
        $d = $this->client->discovery( true ); if ( is_wp_error( $d ) ) { return new WP_Error('wpkc_health',$d->get_error_message(),array('status'=>502)); }
        $j = $this->client->jwks( true ); if ( is_wp_error( $j ) ) { return new WP_Error('wpkc_health',$j->get_error_message(),array('status'=>502)); }
        return array( 'ok'=>true,'issuer'=>$d['issuer'],'authorization_endpoint'=>$d['authorization_endpoint'],'token_endpoint'=>$d['token_endpoint'],'jwks_keys'=>count($j['keys']),'callback_url'=>$this->client->callback_url(),'backchannel_logout_url'=>rest_url('wpkc/v1/backchannel-logout') );
    }

    public function admin_menu(): void { add_options_page( 'Keycloak', 'Keycloak', 'manage_options', 'wpkc', array($this,'settings_page') ); }
    public function admin_init(): void { register_setting( 'wpkc', 'wpkc_settings', array( 'type'=>'array','sanitize_callback'=>array($this,'sanitize_settings'),'default'=>self::defaults() ) ); }
    public function sanitize_settings( $input ): array {
        $old=$this->settings; $in=is_array($input)?$input:array(); $out=self::defaults();
        $url=untrailingslashit( esc_url_raw( trim((string)($in['keycloak_url']??'')) ) ); if($url && 'https'!==wp_parse_url($url,PHP_URL_SCHEME) && !in_array(wp_parse_url($url,PHP_URL_HOST),array('localhost','127.0.0.1','::1'),true)){ add_settings_error('wpkc_settings','wpkc_https','Keycloak URL must use HTTPS except on localhost.'); $url=(string)($old['keycloak_url']??''); }
        $out['keycloak_url']=$url; $out['realm']=sanitize_text_field((string)($in['realm']??'')); $out['client_id']=sanitize_text_field((string)($in['client_id']??''));
        $secret=(string)($in['client_secret']??''); $out['client_secret']='********'===$secret?(string)($old['client_secret']??''):trim( preg_replace( '/[\x00\r\n]+/', '', $secret ) );
        $mode=sanitize_key((string)($in['login_mode']??'optional')); $out['login_mode']=in_array($mode,array('optional','force','disabled'),true)?$mode:'optional';
        foreach(array('jit_provisioning','sync_profile','link_verified_email','link_privileged_email','disable_local_for_linked','rest_bearer','logout_keycloak','debug') as $b){$out[$b]=empty($in[$b])?0:1;}
        $out['role_map']=sanitize_textarea_field((string)($in['role_map']??'')); $out['required_access']=sanitize_textarea_field((string)($in['required_access']??'')); $out['rest_audience']=sanitize_text_field((string)($in['rest_audience']??''));
        delete_transient('wpkc_disc_'.md5((string)($old['keycloak_url']??''))); return $out;
    }

    public function settings_page(): void { if(!current_user_can('manage_options'))return; $s=$this->settings; ?>
<div class="wrap"><h1>WP Keycloak Bridge</h1><p>OIDC callback: <code><?php echo esc_html($this->client->callback_url()); ?></code><br>Backchannel logout URL: <code><?php echo esc_html(rest_url('wpkc/v1/backchannel-logout')); ?></code></p>
<form method="post" action="options.php"><?php settings_fields('wpkc'); ?><table class="form-table" role="presentation">
<?php $this->row('Keycloak URL','keycloak_url','url',$s['keycloak_url'],'https://sso.example.com'); $this->row('Realm','realm','text',$s['realm']); $this->row('Client ID','client_id','text',$s['client_id']); $this->row('Client secret','client_secret','password',$s['client_secret']?'********':''); ?>
<tr><th>Login mode</th><td><select name="wpkc_settings[login_mode]"><?php foreach(array('optional'=>'Optional Keycloak login','force'=>'Force Keycloak login','disabled'=>'Disable interactive Keycloak login') as $v=>$l){echo '<option value="'.esc_attr($v).'" '.selected($s['login_mode'],$v,false).'>'.esc_html($l).'</option>';} ?></select><p class="description">For emergency local access, keep a local administrator account. Force mode does not intercept password-reset/logout actions.</p></td></tr>
<?php foreach(array('jit_provisioning'=>'Create users on first login','sync_profile'=>'Synchronize verified profile data on login','link_verified_email'=>'Link existing accounts by verified email','link_privileged_email'=>'Allow automatic linking to privileged accounts (not recommended)','disable_local_for_linked'=>'Disable WordPress password login/reset for linked Keycloak users','rest_bearer'=>'Enable Keycloak bearer tokens for WordPress REST API','logout_keycloak'=>'Redirect WordPress logout through Keycloak') as $k=>$l){echo '<tr><th>'.esc_html($l).'</th><td><label><input type="checkbox" name="wpkc_settings['.esc_attr($k).']" value="1" '.checked($s[$k],1,false).'> Enabled</label></td></tr>'; } ?>
<?php $this->row('REST token audience','rest_audience','text',$s['rest_audience'],'Defaults to Client ID'); ?>
<tr><th>Role mapping</th><td><textarea class="large-text code" rows="7" name="wpkc_settings[role_map]"><?php echo esc_textarea($s['role_map']); ?></textarea><p class="description">One per line: <code>realm:wordpress-admin=administrator</code>, <code>client:editor=editor</code>, or <code>group:/writers=author</code>.</p></td></tr>
<tr><th>Required Keycloak role/group</th><td><textarea class="large-text code" rows="4" name="wpkc_settings[required_access]"><?php echo esc_textarea($s['required_access']); ?></textarea><p class="description">Optional. One or comma-separated source identifiers. Access is allowed when any matches.</p></td></tr>
</table><?php submit_button(); ?></form>
<h2>Connection test</h2><p><a class="button" href="<?php echo esc_url(add_query_arg('_wpnonce',wp_create_nonce('wp_rest'),rest_url('wpkc/v1/health'))); ?>">Open authenticated health endpoint</a></p></div><?php }
    private function row(string $label,string $name,string $type,string $value,string $placeholder=''):void{ echo '<tr><th><label for="wpkc-'.$name.'">'.esc_html($label).'</label></th><td><input class="regular-text" id="wpkc-'.$name.'" type="'.esc_attr($type).'" name="wpkc_settings['.esc_attr($name).']" value="'.esc_attr($value).'" placeholder="'.esc_attr($placeholder).'" autocomplete="off"></td></tr>'; }
    public function plugin_links(array $links):array{ array_unshift($links,'<a href="'.esc_url(admin_url('options-general.php?page=wpkc')).'">Settings</a>'); return $links; }
    private function log(string $msg):void{ if(!empty($this->settings['debug']) && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG){ error_log('[WP Keycloak Bridge] '.preg_replace('/[\r\n]+/',' ',$msg)); } }
}
