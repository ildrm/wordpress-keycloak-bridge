<?php
/**
 * Plugin Name: WP Keycloak Bridge
 * Plugin URI: https://github.com/ildrm/wordpress-keycloak-bridge
 * Description: Secure OpenID Connect integration between WordPress and Keycloak, including SSO, JIT provisioning, role mapping, logout, backchannel logout, and REST bearer authentication.
 * Version: 1.0.0
 * Requires at least: 6.4
 * Requires PHP: 8.1
 * Author: Shahin Ilderemi
 * Author URI: https://ildrm.com
 * License: GPL-2.0-or-later
 * Text Domain: wp-keycloak-bridge
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'WPKC_VERSION', '1.0.0' );
define( 'WPKC_FILE', __FILE__ );
define( 'WPKC_DIR', plugin_dir_path( __FILE__ ) );

require_once WPKC_DIR . 'includes/class-wpkc-jwt.php';
require_once WPKC_DIR . 'includes/class-wpkc-client.php';
require_once WPKC_DIR . 'includes/class-wpkc-users.php';
require_once WPKC_DIR . 'includes/class-wpkc-plugin.php';

register_activation_hook( __FILE__, array( 'WPKC_Plugin', 'activate' ) );
add_action( 'plugins_loaded', array( 'WPKC_Plugin', 'instance' ) );
