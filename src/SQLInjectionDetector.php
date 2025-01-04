<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class SQLInjectionDetector extends NodeVisitorAbstract
{
    public $variables = [];  

    private $fileName;

    public function __construct($fileName)
    {
        $this->fileName = $fileName;
    }

    public function enterNode(Node $node)
    {
        // Track variable assignments for sanitization
        if ($node instanceof Node\Expr\Assign) {
            $this->trackVariableSanitization($node);
        }

        // Detect method calls (e.g., $wpdb->get_var)
        if ($node instanceof Node\Expr\MethodCall) {
            if ($this->isWpdbQueryMethod($node)) {
                foreach ($node->args as $arg) {
                    if ($this->isVulnerableSQLQuery($arg->value)) {
                        echo "SQL injection detected - $this->fileName:{$node->getLine()}.\n";
                    }
                }
            }
        }
    }

    private function trackVariableSanitization(Node\Expr\Assign $node)
    {
        if ($node->var instanceof Node\Expr\Variable) {
            $varName = $node->var->name;

            // Check if the assigned value is sanitized
            $this->variables[$varName] = $this->isSanitized($node->expr);
        }
    }

    private function isSanitized(Node $node): bool
    {
        // Allow explicit type casting to integer
        if ($node instanceof Node\Expr\Cast\Int_) {
            return true;
        }

        // Allow certain safe functions
        if ($node instanceof Node\Expr\FuncCall) {
            $functionName = $node->name instanceof Node\Name ? $node->name->toString() : null;
            $safeFunctions = ['abs', 'intval', 'floatval', 'esc_sql'];

            return in_array($functionName, $safeFunctions, true);
        }

        return false; // Default to unsafe
    }

    private function isWpdbQueryMethod(Node\Expr\MethodCall $node): bool
    {
        return $node->name instanceof Node\Identifier &&
            in_array($node->name->name, ['get_var', 'query', 'get_results', 'get_row']);
    }

    private function isVulnerableSQLQuery(Node $queryNode): bool
    {
        // Handle raw SQL strings
        if ($queryNode instanceof Node\Scalar\String_) {
            return $this->containsUnsafeVariables($queryNode->value);
        }

        // Handle concatenated queries
        if ($queryNode instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isUnsanitizedInput($queryNode->right);
        }

        // Handle function calls in queries
        if ($queryNode instanceof Node\Expr\FuncCall) {
            $functionName = $queryNode->name instanceof Node\Name ? $queryNode->name->toString() : null;

            // Safe if the function itself is safe
            if (in_array($functionName, ['esc_sql'], true)) {
                return false;
            }
        }

        // Check variables or function calls directly
        return $this->isUnsanitizedInput($queryNode);
    }

    private function isUnsanitizedInput(Node $node): bool
    {
        // Allow explicit type casting to integer
        if ($node instanceof Node\Expr\Cast\Int_) {
            return false; // Safe
        }

        // Allow certain safe functions
        if ($node instanceof Node\Expr\FuncCall) {
            $functionName = $node->name instanceof Node\Name ? $node->name->toString() : null;
            $safeFunctions = ['abs', 'intval', 'floatval', 'esc_sql'];

            return !in_array($functionName, $safeFunctions, true);
        }

        // Flag variables directly used unless sanitized
        if ($node instanceof Node\Expr\Variable) {
            $varName = $node->name;
            return !$this->variables[$varName] ?? true; // Unsafe if not sanitized
        }

        return false; // Default to safe if no conditions match
    }

    private function containsUnsafeVariables(string $query): bool
    {
        return preg_match('/\$[a-zA-Z_][a-zA-Z0-9_]*/', $query);
    }
}
