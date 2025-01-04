<?php 


// Direct user input
$product_id = $_REQUEST['id'];
$wpdb->get_var("SELECT * FROM wp_users WHERE id = " . $product_id); // Vulnerable SQL injection

// Improper use of esc_sql
$variable = $_REQUEST['id'];
$wpdb->get_var("SELECT * FROM wp_users WHERE id = " . esc_sql($variable)); // Vulnerable SQL injection

// // XSS: Outputting unsanitized data
// $variable = $_GET['name'];
// echo $variable; // Vulnerable XSS
