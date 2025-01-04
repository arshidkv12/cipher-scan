<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\ArrayDimFetch;

class LFIDetector extends NodeVisitorAbstract
{
    private $fileName;
    private $variables = [];

    // Constructor to accept the file name
    public function __construct($fileName)
    {
        $this->fileName = $fileName;
    }

    public function enterNode(Node $node)
    {
        // Track variable assignments from superglobals
        if ($node instanceof Node\Expr\Assign) {
            $this->trackVariableSanitization($node);
        }

        // Detecting include statements
        if ($node instanceof Expression && $node->expr instanceof Include_) {
            $this->checkForInclude($node->expr);
        }
    }


    private function trackVariableSanitization(Node\Expr\Assign $node)
    {
        // Get left side (variable)
        $left = $node->var;
        // Get right side (expression)
        $right = $node->expr;

        // Check if the left side is a variable
        if ($left instanceof Variable) {
            $varName = $left->name;
            
            if ($right instanceof ArrayDimFetch) {
                $varName = $right->var->name; // The variable on the right side (e.g., $_GET)
                if ($varName === '_GET' || $varName === '_REQUEST') {
                    $this->variables[$left->name] = 1;
                }
            }
        }
    }

    private function checkForInclude(Include_ $includeNode)
    {
        // Check if the include is using a superglobal like $_GET directly
        if ($includeNode->expr instanceof Variable) {
            $this->checkForSuperGlobalVariable($includeNode->expr);
        }

        // Handle concatenated paths
        if ($includeNode->expr instanceof Concat) {
            $this->checkForConcatenatedPath($includeNode->expr);
        }
    }

    private function checkForSuperGlobalVariable(Variable $variableNode)
    {
        // Check if the variable is $_GET (indicating user input is directly used)
        if ($variableNode->name === '_GET' || $variableNode->name === '_REQUEST') {
            echo "LFI Risk detected - {$this->fileName}:{$variableNode->getLine()}\n";
        }

        if (isset($this->variables[$variableNode->name])) {
            echo "LFI Risk detected - {$this->fileName}:{$variableNode->getLine()}\n";
        }
    }

    private function checkForConcatenatedPath(Concat $concatNode)
    {
        // Check if the concatenation includes user input from $_GET or $_REQUEST
        $left = $concatNode->left;
        $right = $concatNode->right;

        if ($left instanceof Variable && in_array($left->name, ['_GET', '_REQUEST'])) {
            echo "LFI Risk detected - {$this->fileName}:{$concatNode->getLine()} (Concatenated with superglobal)\n";
        }

        if ($right instanceof Variable && in_array($right->name, ['_GET', '_REQUEST'])) {
            echo "LFI Risk detected - {$this->fileName}:{$concatNode->getLine()} (Concatenated with superglobal)\n";
        }
    }


}
