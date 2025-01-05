<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class FunctionCollectorVisitor extends NodeVisitorAbstract
{
    private $functionDefinitions = [];

    public function getFunctionDefinitions()
    {
        return $this->functionDefinitions;
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Stmt\Function_) {
            $this->functionDefinitions[$node->name->toString()] = $node;
        }
    }
}
