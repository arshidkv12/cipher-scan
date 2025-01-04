<?php

namespace SecurityChecker;

use PhpParser\NodeTraverser;

class SecurityIssueDetector
{
    public static function analyze($stmts)
    {
        $traverser = new NodeTraverser;
        foreach (NodeVisitorFactory::create() as $visitor) {
            $traverser->addVisitor($visitor);
        }
        $traverser->traverse($stmts);
    }
}
