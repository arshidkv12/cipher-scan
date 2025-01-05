<?php 


// Direct user input
$product_id = $_REQUEST['id'];
$wpdb->get_var("SELECT * FROM wp_users WHERE id = " . $product_id); // Vulnerable SQL injection


$product_id = (int)$_REQUEST['id'];
$wpdb->get_var("SELECT * FROM wp_users WHERE id = " . $product_id); // Vulnerable SQL injection

// Improper use of esc_sql
$variable = $_REQUEST['id'];
$wpdb->get_var("SELECT * FROM wp_users WHERE id = " . esc_sql($variable)); // Vulnerable SQL injection

// // XSS: Outputting unsanitized data
$variable = 'ds';
$variable1 = $variable;
print($variable1); // Vulnerable XSS

echo $variable; // Vulnerable XSS
$variable = esc_html( $variable );

_e( $variable, 'my-theme' );

