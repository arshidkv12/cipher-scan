<?php

require 'vendor/autoload.php';

use PhpParser\Error;
use PhpParser\ParserFactory;
use SecurityChecker\SecurityIssueDetector;

$parser = (new ParserFactory())->createForNewestSupportedVersion();
$directory = __DIR__ . '/plugin';
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));

foreach ($files as $file) {
    if (pathinfo($file, PATHINFO_EXTENSION) === 'php') {
        try {
            $code = file_get_contents($file);
            $stmts = $parser->parse($code);
            SecurityIssueDetector::analyze($stmts);
        } catch (Error $e) {
            echo "Error parsing file {$file}: {$e->getMessage()}\n";
        }
    }
}
