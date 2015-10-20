/* WP jCryption */
jQuery(document).ready(function($) {
	if ('function' == $.type($.jCryption)) {
		$(wp_jcryption.forms).jCryption({
			getKeysURL: wp_jcryption.keys_url,
			handshakeURL: wp_jcryption.handshake_url,
		});
		if (wp_jcryption.colored) {
			$(wp_jcryption.forms).find(':input').not(':submit').not(':hidden').css('color', '#084');
		}
		if (wp_jcryption.fix_submit) {
			$(wp_jcryption.forms).find(':input#submit').prop('id', 'wpjc-submit');
			$(wp_jcryption.forms).find(':input[name="submit"]').prop('name', 'wpjc-submit');
		}
	}
});

/* Plugin Namescpace
	
*/
//var FormCrypto = FormCrypto || {};
