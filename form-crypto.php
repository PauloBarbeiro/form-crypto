<?php
 
/*
Plugin Name: WP jCryption Security - With Ajax
Version: 0.1
Description: Prevents forms data against sniffing network traffic through encryption provided by jCryption javascript library. Useful for owners of small sites who want to secure their passwords and other posted data but don't want to buy SSL certificate for each domain and subdomain, it protects from sniffing the most important data such as passwords when they are being sent from forms of your site to the server. This plugin also make available to developers, the possibility to use AJAX to validate data, in encrypted way.  (to learn how jCryption works visit jCryption site: www.jcryption.org).
Requires at least: 3.8.1
Tested up to: 4.2.2
Plugin URI: (http://andrey.eto-ya.com/wordpress/my-plugins/wp-jcryption)
Author: Paulo Barbeiro, based on Andrey K.
Author URI: http://paulobarbeiro.com.br (http://andrey.eto-ya.com/)
License: GPL2
License URI: http://www.gnu.org/licenses/gpl-2.0.html

*/

/*
		Copyright 2014 (c) Paulo Barbeiro (URL: http://paulobarbeiro.com.br/, email: paulo@paulobarbeiro.com.br) 

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
 
 
/**
 * This plugin does some awesome stuff upon activation:
 *
 * - Flush rewrite rules (if this has any custom post type or taxonomy)
 * - Display the "About" page whenever there's a new version
 * - Display tooltips
 * - Automatically deactivate itself if some conditions are not met
 *
 *
 */
class FCrypto {
 	const VER = '0.1-dev';
 	const DB_VER = 1;
    /**
     * Setup the environment for the plugin
     */
    public function bootstrap() {
	    global $wp_jcryption_forms;
	    error_log("form-crypto :: BOOTSTRAP ");
	    error_log( serialize($wp_jcryption_forms));
	    
	    register_activation_hook( __FILE__, array( $this, 'activate' ) );
	    
	    define('WPJC_URL', plugins_url(basename(dirname(__FILE__))) . '/');
		define('WPJC_DEFAULT_FORMS', '#loginform, #resetpassform, #your-profile');
		define('WPJC_OPENSSL_ENABLED', function_exists('openssl_encrypt')?true:false);

		if (is_admin()) {
			load_plugin_textdomain('wpjc', false, basename(dirname(__FILE__)) . '/languages');
		}

	    add_action( 'init', array( $this, 'init_rotines' ) );

		add_action('admin_init', array( $this, 'wp_jcryption_admin_init') );
	    add_action( 'admin_menu',  array( $this, 'register_admin_menu' ) );
	    add_action('admin_notices', array( $this, 'wp_jcryption_admin_notices') );

		if (WPJC_OPENSSL_ENABLED) {
			require_once 'libs/sqAES.php';
			require_once 'libs/class-jcryption.php';
		
			add_action('plugins_loaded', array( $this, 'wp_jcryption_entry') );
			add_action('wp_enqueue_scripts', array( $this, 'wp_jcryption_enqueue') );
			add_action('admin_enqueue_scripts', array( $this, 'wp_jcryption_admin_enqueue_scripts') );
			add_action('login_enqueue_scripts', array( $this, 'wp_jcryption_scripts') );
			add_action('login_enqueue_scripts', array( $this, 'wp_jcryption_style') );
			add_action('login_form', array( $this, 'wp_jcryption_login_form') );
		}
		
		//add_action( 'wp_ajax_teste_callback', 'teste_callback' );
		//add_action( 'wp_ajax_nopriv_teste_callback', 'teste_callback' );

    }//bootstrap
    
    /*
	  Init  
    */
    public function init_rotines(){
		// register some post types and taxonomies here
		global $wp_jcryption_forms;
	    error_log("form-crypto :: init_rotines ");
	    error_log( serialize($wp_jcryption_forms));
	    if( isset($wp_jcryption_forms['ajax_fields']) && isset($wp_jcryption_forms['ajax_callbacks']) ){
		    if( $wp_jcryption_forms['ajax_fields'] ){
			    
			    $callbacks = $wp_jcryption_forms['ajax_callbacks'];
			    $callbacks_list = explode(",", $callbacks);
			    
			    foreach( $callbacks_list as $callback ){
				    error_log( "creatings AJAX call:: wp_ajax_".$callback." -> ".$callback );
				    add_action( 'wp_ajax_'.$callback, $callback );
					add_action( 'wp_ajax_nopriv_'.$callback, $callback );
			    }
			    
		    }
	    }
	    //add_action( 'wp_ajax_email_validation', array($this,'email_validation_callback') );
		//add_action( 'wp_ajax_nopriv_email_validation', array($this,'email_validation_callback') );
		//*/
	}

	function wp_jcryption_style() {
		wp_enqueue_style('wp-jcryption-login', WPJC_URL . 'style.css');
	}

	function wp_jcryption_scripts() {
		global $wp_jcryption_forms;
		wp_register_script('jcryption', WPJC_URL . 'js/jcryption/jquery.jcryption-min.js', array('jquery'), '3.1.0', true );
		wp_register_script('wp-jcryption', WPJC_URL . 'js/forms.js', array('jcryption', 'jquery'), null, true );
		
		if ($wp_jcryption_forms['ajax_fields']){
			wp_localize_script( 'wp-jcryption', 'AjaxValidations', array( 'url' => admin_url( 'admin-ajax.php' ) ) );
		}
		
		$location = array(
			'keys_url' => home_url('/index.php?wp_jcryption_entry=getPublicKey'),
			'handshake_url' => home_url('/index.php?wp_jcryption_entry=handshake'),
			'forms' => $wp_jcryption_forms['forms'],
			'fix_submit' => empty($wp_jcryption_forms['fix_submit']) ? false : true,
			'colored' => empty($wp_jcryption_forms['colored']) ? false : true,
			'use_ajax_fields' => empty($wp_jcryption_forms['ajax_fields']) ? false : true,
			'nonce' =>  wp_create_nonce( NONCE_SALT ),
		);
		wp_localize_script('wp-jcryption', 'wp_jcryption', $location);
		wp_enqueue_script('wp-jcryption');
		
		
	}
	
	function wp_jcryption_enqueue() {
		global $wp_jcryption_forms;
		if ($wp_jcryption_forms['forms'] != WPJC_DEFAULT_FORMS) {
			$this->wp_jcryption_scripts();
		}
		
		
		
	}

	function wp_jcryption_admin_enqueue_scripts($hook) {
		global $wp_jcryption_forms;
		if (!empty($wp_jcryption_forms['in_admin']) || in_array($hook, array('profile.php', 'user-edit.php'))) {
			$this->wp_jcryption_scripts();	
		}
	}
	
	function wp_jcryption_login_form() {
		echo  '<p class="wpjc-secured-by">' . 'Secured by WP jCryption' . '</p>';
	}
	/**
	 * Do some stuff upon activation
	 */
	public function activate() {
		$this->check_dependencies();
		$this->init_options();
		// Important if custom post types, or custom taxonomies were created.
		// flush_rewrite_rules();
	}
	
	public function check_dependencies() {
		// do nothing if class bbPress exists
		if ( ! function_exists('openssl_encrypt') ) {
			trigger_error( 'This plugin requires OpenSSL library on your PHP instalation. Please install.', E_USER_ERROR );
		}
	}
	
	public function init_options() {
		if (!WPJC_OPENSSL_ENABLED) {
			return;
		}
		
		update_option( 'fCrypto_ver', self::VER );
		update_option( 'fCrypto_db_ver', self::DB_VER );
		
		
		$option = get_option('wp_jcryption');
		if ($option) {
			$notice['updated'][] = sprintf(__('RSA keys have been created before: %s', 'wpjc'), date('j M Y H:i:s T', $option['ts']));
			update_option('_wp_jcryption_notice', $notice);
		}
		else {
			$this->wp_jcryption_generate_keys();
		}
		if (!get_option('wp_jcryption_forms')) {
			add_option('wp_jcryption_forms', array('forms' => WPJC_DEFAULT_FORMS, 'colored' => '1', 'fix_submit' => '1')); // <<<<<<<<<<<<<<<<<<< IMPORTANT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
		}
	}
	
	
	/*
	 *	REGISTER MENUS AND CONFIG PAGES
	 */
	public function register_admin_menu() {

		add_options_page('WP JCryption Settings', 'WP jCryption', 'manage_options', 'wp_jcryption', array( $this,'wp_jcryption_settings_page') );
		add_action('admin_init', array( $this,'wp_jcryption_register_settings' ) );

	}
	 
 
	/*
	 *	JCrypto
	 */
	 
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


	
	function wp_jcryption_register_settings() {
		register_setting('wpjc-group-1', 'wp_jcryption_forms', array($this,'wp_jcryption_sanitize'));
		register_setting('wpjc-group-2', 'wp_jcryption_length', array($this,'wp_jcryption_generate_keys'));
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
			
			
			
			<h4><label for="forms"><?php _e('Fields AJAX Validation', 'wpjc'); ?></label></h4>
				
			<p><input type="checkbox" name="wp_jcryption_forms[ajax_fields]" value="1" <?php echo empty($wp_jcryption_forms['ajax_fields']) ? '':'checked'; ?> />
			<?php _e('Use ajax for form fields validations', 'wpjc'); ?></p>
			
			<p><input type="text" size="76" name="wp_jcryption_forms[ajax_callbacks]" value="<?php
					echo (isset($wp_jcryption_forms['ajax_callbacks']))?$wp_jcryption_forms['ajax_callbacks']:""; ?>" /></p>
			<p>	<span class="description"><?php _e('Name the callback functions for your form fields(??in jQuery style, separated by commas), e. g.:', 'wpjc'); ?></span> <code>#commentform, #createuser</code></p>
			
			
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
		error_log("wp_jcryption_sanitize :::::: ");
		error_log( serialize($input) );
		
		$forms = preg_replace('/[^ a-z0-9_#,\.-]/i', '', $input['forms']);
		$list = explode(',', $forms);
		
		$callbacks = preg_replace('/[^ a-z0-9_#,\.-]/i', '', $input['ajax_callbacks']);
		$list_callbacks = explode(',', $callbacks);
		
		//list of forms for encryption
		foreach ($list as $key => $item) {
			$list[$key] = trim(preg_replace('/ +/', ' ', $item));
			if ('' == $list[$key]) {
				unset($list[$key]);
			}
		}
		
		//list of callbacks
		foreach ($list_callbacks as $key => $item) {
			$list_callbacks[$key] = trim(preg_replace('/ +/', ' ', $item));
			if ('' == $list_callbacks[$key]) {
				unset($list_callbacks[$key]);
			}
		}
		
		$list[] = '#loginform';
		$list[] = '#resetpassform';
		$list[] = '#your-profile';
		foreach (array('in_admin', 'colored', 'fix_submit', 'ajax_fields') as $key) {
			if (!empty($input[$key]))
				$out[$key] = '1';
		}
		sort($list);
		$list = array_unique($list);
		$out['forms'] = implode(', ', $list);
		
		sort($list_callbacks);
		$list_callbacks = array_unique($list_callbacks);
		$out['ajax_callbacks'] = implode(', ', $list_callbacks);
		
		//error_log(serialize($list));
		//error_log(serialize($out));
		
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
	
	function wp_jcryption_decrypt_entry($value) {
		
		$jc = new wp_jcryption;
			
			//error_log("wp_jcryption_decrypt_entry :: ".$value);
			//error_log(serialize($_SESSION));
			
			return $jc->decrypt_one($value);
		
		//if (!empty($_GET['wp_jcryption_entry'])) {
		//	$jc->go();
		//}
	}
	
	public function validate_nonces($nonce){
		
		if ( ! wp_verify_nonce( $nonce, NONCE_SALT ) ) {
			    // This nonce is not valid.
			    //die( 'Security check' ); 
			    return false;
		} 
		
		return true;
	}
	
	

 
}


 
global $fcrypto_plugin;
$fcrypto_plugin = new FCrypto();
$fcrypto_plugin->bootstrap();


function fcrypto_validate_nonce($nonce){
	global $fcrypto_plugin;
	return $fcrypto_plugin->validate_nonces($nonce);
}

function fcrypto_decryptPost($value){
	global $fcrypto_plugin;
	error_log("fcrypto_decryptPost :: ".$value);
	return $fcrypto_plugin->wp_jcryption_decrypt_entry($value);
}
