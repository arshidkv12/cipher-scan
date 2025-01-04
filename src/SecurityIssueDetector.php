<?php

namespace SecurityChecker;

use PhpParser\NodeTraverser;

class SecurityIssueDetector
{
    public static function analyze($stmts, $fileName)
    {
        $traverser = new NodeTraverser;
        foreach (NodeVisitorFactory::create($fileName) as $visitor) {
            $traverser->addVisitor($visitor);
        }
        $traverser->traverse($stmts);
    }
}
