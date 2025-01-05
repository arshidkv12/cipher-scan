<?php
// add_action('wp_ajax_update_settings', function() {
//     update_option("my_settings", $_POST);
// });


// add_action('wp_ajax_update_settings', 'api_ajax');

// function api_ajax() {
//     update_option("my_settings", $_POST);
// }

add_action('wp_ajax_update_settings', 'api_ajax_nonce');

function api_ajax_nonce() {
	check_ajax_referer( 'wpdocs-special-string', 'security' );
    update_option("my_settings", $_POST);
}