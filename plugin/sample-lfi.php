<?php 

add_action("wp_ajax_nopriv_render_lesson", "render_lesson_template");

function render_lesson_template(){
    $template_path      = $_GET['template_path'];

    // For custom template return all list of lessons
    include $template_path;
    die();
}