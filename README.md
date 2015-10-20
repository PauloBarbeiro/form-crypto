#Form-crypto

Wordpress plugin to encrypt information traffic, without SSL Certification

This plugin is a modification from WP jCryption Security, by Andrey K. (https://wordpress.org/plugins/wp-jcryption/)

Prevents forms data against sniffing network traffic through encryption provided by jCryption javascript library. Useful for owners of small sites who want to secure their passwords and other posted data but don't want to buy SSL certificate for each domain and subdomain, it protects from sniffing the most important data such as passwords when they are being sent from forms of your site to the server. This plugin also make available to developers, the possibility to use AJAX to validate data, in encrypted way.  (to learn how jCryption works visit jCryption site: www.jcryption.org).

= How to use it

To encrypt your forms, or fields for ajax validations, you must setup the plugin :: Settings Panel > FormCrypto :
	- inform the plugin the form identification
	- inform if you want use ajax to validate some fields
	- name the callback functions to treat the ajax information
	- give the ajaxcallback attribute to each input field you want to validate. eg: <input type="text" name="username" ajaxcallback="username_callback">
	- create a function, in your functions.php theme file, to treat the ajax info, and return some information
	- create some callback function in your js file, to give a user visual feedback.

See the video for more details:
	

	
	
	