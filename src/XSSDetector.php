<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class XSSDetector extends NodeVisitorAbstract
{
    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Stmt\Echo_ || $node instanceof Node\Expr\FuncCall) {
            foreach ($node->exprs ?? $node->args as $expr) {
                if ($this->isUnsanitizedInput($expr->value ?? $expr)) {
                    echo "Potential XSS vulnerability in output at line {$node->getLine()}.\n";
                }
            }
        }
    }

    private function isUnsanitizedInput(Node $node): bool
    {
        if ($node instanceof Node\Expr\Variable) {
            return true;
        }

        if ($node instanceof Node\Expr\FuncCall) {
            $functionName = $node->name instanceof Node\Name ? $node->name->toString() : null;
            if (in_array($functionName, ['esc_html', 'esc_attr', 'sanitize_text_field'])) {
                return false;
            }
        }

        return true;
    }
}
