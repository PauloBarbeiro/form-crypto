<?php
/*
Plugin Name: Form Crypto
Version: 0.1
Description: Prevents forms data against sniffing network traffic through encryption provided by jCryption javascript library. Useful for owners of small sites who want to secure their passwords and other posted data but don't want to buy SSL certificate for each domain and subdomain, it protects from sniffing the most important data such as passwords when they are being sent from forms of your site to the server (to learn how jCryption works visit jCryption site: www.jcryption.org).
Requires at least: 3.8.1
Tested up to: 4.2.2
Plugin URI: 
Author: Paulo Barbeiro
Author URI: 
License: GPL2
License URI: http://www.gnu.org/licenses/gpl-2.0.html

*/

/*
		Copyright 2014 (c) Andrey K. (URL: http://andrey.eto-ya.com/, email: andrey271@bigmir.net)

		This program is free software; you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation; either version 2 of the License, or
		(at your option) any later version.

		This program is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		GNU General Public License for more details.

		You should have received a copy of the GNU General Public License
		along with this program; if not, write to the Free Software
		Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

*/

/*
		This plugin includes jquery.jcryption.js and uses PHP code by Daniel Griesser http://www.jcryption.org/
		Copyright (c) 2013 Daniel Griesser
		MIT license.
		http://www.opensource.org/licenses/mit-license.php
*/

define('WPJC_URL', plugins_url(basename(dirname(__FILE__))) . '/');
define('WPJC_DEFAULT_FORMS', '#loginform, #resetpassform, #your-profile');
define('WPJC_OPENSSL_ENABLED', function_exists('openssl_encrypt')?true:false);

add_action('admin_init', 'wp_jcryption_admin_init');
add_action('admin_menu', 'wp_jcryption_create_menu');
add_action('admin_notices', 'wp_jcryption_admin_notices');

if (WPJC_OPENSSL_ENABLED) {
	require_once 'sqAES.php';
	require_once 'class-jcryption.php';

	add_action('plugins_loaded', 'wp_jcryption_entry');
	add_action('wp_enqueue_scripts', 'wp_jcryption_enqueue');
	add_action('admin_enqueue_scripts', 'wp_jcryption_admin_enqueue_scripts');
	add_action('login_enqueue_scripts', 'wp_jcryption_scripts');
	add_action('login_enqueue_scripts', 'wp_jcryption_style');
	add_action('login_form', 'wp_jcryption_login_form');
}

if (is_admin()) {
	load_plugin_textdomain('wpjc', false, basename(dirname(__FILE__)) . '/languages');
}

function wp_jcryption_scripts() {
	global $wp_jcryption_forms;
	wp_register_script('jcryption', WPJC_URL . 'jcryption/jquery.jcryption-min.js', array('jquery'), '3.1.0', true );
	wp_register_script('wp-jcryption', WPJC_URL . 'forms.js', array('jcryption', 'jquery'), null, true );
	$location = array(
		'keys_url' => home_url('/index.php?wp_jcryption_entry=getPublicKey'),
		'handshake_url' => home_url('/index.php?wp_jcryption_entry=handshake'),
		'forms' => $wp_jcryption_forms['forms'],
		'fix_submit' => empty($wp_jcryption_forms['fix_submit']) ? false : true,
		'colored' => empty($wp_jcryption_forms['colored']) ? false : true,
	);
	wp_localize_script('wp-jcryption', 'wp_jcryption', $location);
	wp_enqueue_script('wp-jcryption');
}

function wp_jcryption_style() {
	wp_enqueue_style('wp-jcryption-login', WPJC_URL . 'style.css');
}

function wp_jcryption_enqueue() {
	global $wp_jcryption_forms;
	if ($wp_jcryption_forms['forms'] != WPJC_DEFAULT_FORMS) {
		wp_jcryption_scripts();
	}
}

function wp_jcryption_admin_enqueue_scripts($hook) {
	global $wp_jcryption_forms;
	if (!empty($wp_jcryption_forms['in_admin']) || in_array($hook, array('profile.php', 'user-edit.php'))) {
		wp_jcryption_scripts();	
	}
}

function wp_jcryption_admin_init() {
	if (!WPJC_OPENSSL_ENABLED) {
		if (current_user_can('manage_options')) {
			$notice['error']['need_openssl'] = __('WP jCryption is not working currently because it requires PHP 5.3+ with OpenSSL extension.', 'wpjc');
			update_option('_wp_jcryption_notice', $notice);
		}
		return;
	}
	if (!get_option('wp_jcryption')) {
		$notice['error']['keys_not_found'] = __('Public and private keys have not been generated yet.', 'wpjc');
		return;
	}
}

function wp_jcryption_login_form() {
	echo  '<p class="wpjc-secured-by">' . 'Secured by WP jCryption' . '</p>';
}

register_activation_hook(__FILE__, 'wp_jcryption_install');

function wp_jcryption_install() {
	if (!WPJC_OPENSSL_ENABLED) {
		return;
	}
	$option = get_option('wp_jcryption');
	if ($option) {
		$notice['updated'][] = sprintf(__('RSA keys have been created before: %s', 'wpjc'), date('j M Y H:i:s T', $option['ts']));
		update_option('_wp_jcryption_notice', $notice);
	}
	else {
		wp_jcryption_generate_keys();
	}
	if (!get_option('wp_jcryption_forms')) {
		add_option('wp_jcryption_forms', array('forms' => WPJC_DEFAULT_FORMS, 'colored' => '1', 'fix_submit' => '1'));
	}
}

function wp_jcryption_admin_notices() {
	$notices = get_option('_wp_jcryption_notice');
	if ($notices) {
		foreach ($notices as $type => $arr) {
			foreach ($arr as $content) {
				echo '<div class="'. $type . '"><p>' . $content . ' </p></div>';
			}
		}
		delete_option('_wp_jcryption_notice');
	}
}

function wp_jcryption_create_menu() {
	add_options_page('WP JCryption Settings', 'WP jCryption', 'manage_options', 'wp_jcryption', 'wp_jcryption_settings_page');
	add_action('admin_init', 'wp_jcryption_register_settings' );
}

function wp_jcryption_register_settings() {
	register_setting('wpjc-group-1', 'wp_jcryption_forms', 'wp_jcryption_sanitize');
	register_setting('wpjc-group-2', 'wp_jcryption_length', 'wp_jcryption_generate_keys');
}

function wp_jcryption_settings_page() {
	global $wp_jcryption_forms;
	$key = get_option('wp_jcryption');
?>
<div class="wrap">
<h2>WP JCryption</h2>
<form method="post" action="options.php">
	<?php settings_fields('wpjc-group-1'); ?>
	<?php do_settings_sections('wpjc-group-1'); ?>
	<h3><label for="forms"><?php _e('Form selectors', 'wpjc'); ?></label></h3>
	<p><input type="text" size="76" name="wp_jcryption_forms[forms]" value="<?php
		echo $wp_jcryption_forms['forms']; ?>" /></p>
	<p>	<span class="description"><?php _e('List forms which data are to be encrypted (in jQuery style, separated by commas), e. g.:', 'wpjc'); ?></span> <code>#commentform, #createuser</code></p>
	<p><input type="checkbox" name="wp_jcryption_forms[in_admin]" value="1" <?php echo empty($wp_jcryption_forms['in_admin']) ? '':'checked'; ?> />
	<?php _e('Also use in admin area (user profile form data will be encrypted anyway)', 'wpjc'); ?></p>

	<p><input type="checkbox" name="wp_jcryption_forms[colored]" value="1" <?php echo empty($wp_jcryption_forms['colored']) ? '':'checked'; ?> />
	<?php _e('Indicate secured form inputs with color', 'wpjc'); ?></p>

	<p><input type="checkbox" name="wp_jcryption_forms[fix_submit]" value="1" <?php echo empty($wp_jcryption_forms['fix_submit']) ? '':'checked'; ?> />
	<?php _e('Fix button id=&#34;submit&#34; and name=&#34;submit&#34; by replacing this with &#34;wpjc-submit&#34;', 'wpjc'); ?></p>
	<?php submit_button(); ?>
</form>
<form method="post" action="options.php">
	<?php settings_fields('wpjc-group-2'); ?>
	<?php do_settings_sections('wpjc-group-2'); ?>
	<h3><?php _e('Current Key Pair', 'wpjc'); ?></h3>
	<p><?php
		$length = strlen(base64_decode($key['public']));
		$bits = 1024 * floor(($length - 50)/128);
		printf(__('Generation date: %s. Current RSA public key length: %d.', 'wpjc'), date('j M Y H:i:s T', $key['ts']), $bits); ?>
	</p>
	<p><pre><?php echo $key['public']; ?></pre></p>
	<p><?php _e('Private key is not shown here but it is stored in the database.', 'wpjc'); ?></p>
	<p><b><?php _e('New key length:', 'wpjc'); ?></b>
	<select name="wp_jcryption_length">
<?php
	foreach (array(1024, 2048, 4096) as $value) {
		echo '<option value="' . $value . '"' . ($value == $bits ? ' selected="selected"' :'' ) . '>' . $value . '</option>';
	}
?>
	</select> &nbsp; &nbsp; 
<?php submit_button( __('Generate new key pair', 'wpjc'), 'primary', 'generate-key-pair', false); ?>
	</p>
</form>
</div>
<?php
}

function wp_jcryption_sanitize($input) {
	$forms = preg_replace('/[^ a-z0-9_#,\.-]/i', '', $input['forms']);
	$list = explode(',', $forms);
	foreach ($list as $key => $item) {
		$list[$key] = trim(preg_replace('/ +/', ' ', $item));
		if ('' == $list[$key]) {
			unset($list[$key]);
		}
	}
	$list[] = '#loginform';
	$list[] = '#resetpassform';
	$list[] = '#your-profile';
	foreach (array('in_admin', 'colored', 'fix_submit') as $key) {
		if (!empty($input[$key]))
			$out[$key] = '1';
	}
	sort($list);
	$list = array_unique($list);
	$out['forms'] = implode(', ', $list);
	return $out;
}

function wp_jcryption_generate_keys($input = 1024) {
	if (!in_array($input, array('1024', '2048', '4096'))) {
		$input = 1024;
	}
	$config = array(
		'digest_alg'=> 'sha1',
		'private_key_bits' => (int)$input,
		'private_key_type' => OPENSSL_KEYTYPE_RSA,
	);

	$res = openssl_pkey_new($config);
	openssl_pkey_export($res, $private_key);

	$public_key = openssl_pkey_get_details($res);
	$public_key = $public_key['key'];
	
	if (strlen($private_key) < $input/2) {
		$notice['error'][] = __('Public or private keys have not been generated correctly.', 'wpjc');
		return;
	}
	if (!get_option('wp_jcryption')) {
		$link = sprintf('<a href="%s">%s</a>', admin_url('options-general.php?page=wp_jcryption'), __('plugin settings', 'wpjc'));
		$notice['updated'][] = sprintf(__('Maybe you want to change some %s.', 'wpjc'), $link);
	}

	$key['public'] = $public_key;
	$key['private'] = $private_key;
	$key['ts'] = time();
	update_option('wp_jcryption', $key);
	$notice['updated'][] = sprintf(__('Public and private keys have been generated successfully, %s.', 'wpjc'), date('j M Y, H:i:s', $key['ts']));
	update_option('_wp_jcryption_notice', $notice);
	return false;
}

/* jCryption server entry point - handles handshake, getPublicKey,
 * decrypts posted form data, does decrypttest, dumps posted form data.
 * Based on example from php/jcryption.php of jCryption package (www.jcryption.org) 
 */
function wp_jcryption_entry() {
	global $wp_jcryption_forms;
	$wp_jcryption_forms = get_option('wp_jcryption_forms');
	$jc = new wp_jcryption;
	if (!empty($_POST['jCryption'])) {
		$jc->decrypt();
	}
	if (!empty($_GET['wp_jcryption_entry'])) {
		$jc->go();
	}
}
