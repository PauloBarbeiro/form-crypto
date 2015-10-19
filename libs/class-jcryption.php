<?php
/* Based on the 'jcryption' class from php/include/jcryption.php of jCryption package (www.jcryption.org) */

class wp_jcryption
{
	private $private_key;
	private $public_key;

	const SESSION_KEY = 'jCryptionKey';
	const POST_KEY = 'jCryption';

	public function __construct()
	{
		$key = get_option('wp_jcryption');
		if (empty($key['public']) || empty($key['private'])) {
			if (is_admin()) {
				include_once ABSPATH . '/wp-admin/includes/plugin.php';
				deactivate_plugins(dirname(__FILE__) . '/wp-jcryption.php');
				$message = __('Unable to read RSA keys. WP jCryption plugin has been deactivated. %s', 'wpjc');
				wp_die(sprintf($message, ' <a href="' . admin_url('/') . '">' . __('Back to admin area', 'wpjc') . '</a>'));
			}
			else {
				throw new Exception('Unable to read RSA keys');
			}
		}
		$this->public_key = $key['public'];
		$this->private_key = $key['private'];
		$this->session_start();
	}

	public function getPublicKey()
	{
		header('Content-Type: application/json');
		echo json_encode(array('publickey' => $this->public_key));
		exit;
	}

	public function handshake()
	{
		openssl_private_decrypt(@base64_decode($_POST['key']), $key, $this->private_key);
		$_SESSION[self::SESSION_KEY] = $key;
		header('Content-Type: application/json');
		$out = json_encode(array('challenge' => sqAES::crypt($key, $key)));
		echo $out;
		exit;
	}

	public function decrypttest()
	{
		date_default_timezone_set('UTC');
		$toEncrypt = date('c');
		$key = $_SESSION[self::SESSION_KEY];
		$encrypted = sqAES::crypt($key, $toEncrypt);
		header('Content-Type: application/json');
		echo json_encode(
			array(
				'encrypted' => $encrypted,
				'unencrypted' => $toEncrypt,
			)
		);
		exit;
	}

	public static function decrypt()
	{
		self::session_start();
		
		error_log( "form-crypto::jcrypto.php::Decrypt called" );
		//error_log( serialize($_POST) );
		
		parse_str(sqAES::decrypt($_SESSION[self::SESSION_KEY], $_POST[self::POST_KEY]), $_POST);
		//error_log( serialize($_POST) );
		
		unset($_REQUEST[self::POST_KEY]);
		$_REQUEST = array_merge($_POST, $_REQUEST);
		
		//error_log( serialize($_REQUEST) );
	}
	
	public static function decrypt_one($value)
	{
		//self::session_start();
		
		error_log( "form-crypto::jcrypto.php::Decrypt_ONE called :: ".$value );
		//error_log( serialize($_POST) );
		$return_value = sqAES::decrypt($_SESSION[self::SESSION_KEY], $value);
		
		//parse_str(sqAES::decrypt($_SESSION[self::SESSION_KEY], $value), $return_value);
		//parse_str(sqAES::decrypt($_SESSION[self::SESSION_KEY], $_POST[self::POST_KEY]), $value);
		//error_log( serialize($_POST) );
		
		//unset($_REQUEST[self::POST_KEY]);
		//$_REQUEST = array_merge($_POST, $_REQUEST);
		return $return_value;
		//error_log( serialize($_REQUEST) );
	}

	public function go()
	{
		error_log("form-crypto::jcrypto.php::Go called");
		
		if (!empty($_GET['wp_jcryption_entry'])) {
			
			error_log("form-crypto::jcrypto.php::Go NOT EMPTY GET : ".$_GET['wp_jcryption_entry'] );
			
			switch ($_GET['wp_jcryption_entry']) {
				case 'getPublicKey':
					$this->getPublicKey();
					break;
				case 'handshake':
					$this->handshake();
					break;
				case 'decrypttest':
					$this->decrypttest();
					break;
			}
		}
		if (isset($_POST[self::POST_KEY])) {
			
			error_log("form-crypto::jcrypto.php::Go POST_KEY IS SET");
			//error_log($_POST[self::POST_KEY]);
			//error_log( serialize($_POST) );
			
			$this->decrypt();
			unset($_SESSION[self::SESSION_KEY]);
		}
	}


	public static function session_start()
	{
		error_log("form-crypto::jcrypto.php::Session_start called");
		
		if (!session_id())
			//error_log("form-crypto::jcrypto.php::Session_start New Session will be started");
			session_start();
	}
}
