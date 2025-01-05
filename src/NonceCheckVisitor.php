<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Expr\FuncCall;

class NonceCheckVisitor extends NodeVisitorAbstract
{
    private $fileName;
    private $functionDefinitions;

    public function __construct($fileName, array $functionDefinitions)
    {
        $this->fileName = $fileName;
        $this->functionDefinitions = $functionDefinitions;
    }

    public function enterNode(Node $node)
    {
        // Analyze `add_action` callbacks (logic remains unchanged)
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name && $node->name->toString() === 'add_action') {
            $actionName = $node->args[0]->value;
            $callback = $node->args[1]->value;

            if ($actionName instanceof Node\Scalar\String_ && str_starts_with($actionName->value, 'wp_ajax_')) {
                if ($callback instanceof Node\Expr\Closure) {
                    $hasNonceCheck = $this->checkForNonce($callback->stmts);
                    if (!$hasNonceCheck) {
                        echo "$actionName->value : No nonce - $this->fileName:{$node->getLine()}\n";
                    }
                } elseif ($callback instanceof Node\Scalar\String_ && isset($this->functionDefinitions[$callback->value])) {
                    $functionNode = $this->functionDefinitions[$callback->value];
                    $hasNonceCheck = $this->checkForNonce($functionNode->stmts);
                    if (!$hasNonceCheck) {
                        echo "$actionName->value : No nonce in function $callback->value - $this->fileName:{$functionNode->getLine()}\n";
                    }
                }
            }
        }
    }

    private function checkForNonce(array $stmts): bool
    {
        foreach ($stmts as $stmt) {  

            if ($stmt instanceof Node\Stmt\Expression) {
                $expr = $stmt->expr;
    
                if ($expr instanceof Node\Expr\FuncCall) {
                    $functionName = $expr->name->toString();
    
                    if ($functionName === 'check_ajax_referer') {
                        $args = $expr->args;
                        if (count($args) == 2) {
                            return true;  
                        }
                    }
                }
            }
    
            if ($stmt instanceof If_) {
                $condition = $stmt->cond;
    
                // Check if the condition is a boolean negation (!)
                if ($condition instanceof Node\Expr\BooleanNot) {
                    $innerExpr = $condition->expr;
    
                    // Check if the inner expression is a function call
                    if ($innerExpr instanceof FuncCall) {
                        // Check the function name
                        if ($innerExpr->name instanceof Node\Name
                            && $innerExpr->name->toString() === 'wp_verify_nonce') {
                            return true;
                        }
                    }
                }
            }
        }
    
        return false;
    }
    
}
