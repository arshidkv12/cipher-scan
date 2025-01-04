<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

class FileUploadDetector extends NodeVisitorAbstract
{
    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Expr\FuncCall) {
            $functionName = $node->name instanceof Node\Name ? $node->name->toString() : null;

            if (in_array($functionName, ['move_uploaded_file', 'file_put_contents'])) {
                if (!$this->isSanitizedInput($node)) {
                    echo "Potential file upload vulnerability in `{$functionName}` at line {$node->getLine()}.\n";
                }
            }
        }
    }

    private function isSanitizedInput(Node\Expr\FuncCall $node): bool
    {
        foreach ($node->args as $arg) {
            $argValue = $arg->value;

            if ($argValue instanceof Node\Expr\FuncCall) {
                $calledFunction = $argValue->name instanceof Node\Name ? $argValue->name->toString() : null;
                if (in_array($calledFunction, ['sanitize_file_name', 'wp_check_filetype'])) {
                    return true;
                }
            }
        }

        return false;
    }
}
