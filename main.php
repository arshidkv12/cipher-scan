<?php

require 'vendor/autoload.php';

use PhpParser\Error;
use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use SecurityChecker\FunctionCollectorVisitor;
use SecurityChecker\NodeVisitorFactory;

$directory = __DIR__ . '/plugin';
$parser = (new ParserFactory())->createForNewestSupportedVersion();

$directoryIterator = new RecursiveDirectoryIterator($directory);

// Use CallbackFilterIterator to filter out the vendor folder
$iterator = new RecursiveIteratorIterator($directoryIterator);
$files = new CallbackFilterIterator($iterator, function($current, $key, $iterator) {
    // Skip the vendor directory
    return strpos($current->getPathname(), '/vendor/') === false;
});

foreach ($files as $file) {
    if (pathinfo($file, PATHINFO_EXTENSION) === 'php') {
        try {
            $code = file_get_contents($file);
            $stmts = $parser->parse($code);

            // Step 1: Collect functions
            $functionCollector = new FunctionCollectorVisitor();
            $traverser = new NodeTraverser();
            $traverser->addVisitor($functionCollector);
            $traverser->traverse($stmts);

            // Get collected function definitions
            $functionDefinitions = $functionCollector->getFunctionDefinitions();

            // Step 2: Run security checks
            $visitors = NodeVisitorFactory::create($file, $functionDefinitions);
            $traverser = new NodeTraverser();
            foreach ($visitors as $visitor) {
                $traverser->addVisitor($visitor);
            }
            $traverser->traverse($stmts);
        } catch (Error $e) {
            echo "Error parsing file {$file}: {$e->getMessage()}\n";
        }
    }
}
