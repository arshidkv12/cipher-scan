<?php 

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node\Stmt\Echo_;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\ArrayDimFetch;

class XSSDetector extends NodeVisitorAbstract
{
    private $variables = [];
    private $fileName;

    public function __construct($fileName)
    {
        $this->fileName = $fileName;
    }

    public function enterNode(Node $node)
    { 
        // Track assignments of user input like $_GET or $_REQUEST
        if ($node instanceof Node\Expr\Assign) {
            $this->trackUserInputAssignment($node);
            $this->trackVariableSanitization($node);
        }

        // Check for echo statements
        if ($node instanceof Echo_) {
            $this->checkForEcho($node);
        }

        // Check for print statements
        if ($node instanceof Print_) {
            $this->checkForPrint($node);
        }

        if ($node instanceof FuncCall && $node->name instanceof Node\Name) {
            $this->checkForEFunctionCall($node);
        }
    }

    private function checkForEcho(Echo_ $node)
    {
        // Loop through expressions in echo
        foreach ($node->exprs as $expr) {
            // Check if the expression is a variable (could be user input)
            if ($expr instanceof Variable) {
                // Check if the assigned value is sanitized
                $varName = $expr->name;
                if (!$this->variables[$varName]) {
                    echo "XSS Risk detected - {$this->fileName}:{$node->getLine()} \n";
                }
            }
        }
        return false;
    }

    private function checkForPrint(Print_ $node)
    {
        // Check the expression being printed
        $expr = $node->expr;
        if ($expr instanceof Variable) {
            $varName = $expr->name;
            if (!$this->variables[$varName]) {
                echo "XSS Risk detected - {$this->fileName}:{$node->getLine()} \n";
            }        
        }
    }

    private function checkForEFunctionCall(FuncCall $node)
    {
        // Check if the function name is '_e'
        if ($node->name->toString() === '_e') {
            // Check if the first argument is a variable (could be user input)
            if ($node->args[0]->value instanceof Variable) {
                $varName = $node->args[0]->value->name;
                if (!$this->variables[$varName]) {
                    echo "XSS Risk detected - {$this->fileName}:{$node->getLine()} \n";
                }            
            }
        }
    }

    private function trackVariableSanitization(Node\Expr\Assign $node)
    {
        if ($node->var instanceof Node\Expr\Variable) {
            $varName = $node->var->name;

            if( !$this->variables[$varName]){ 
                $this->variables[$varName] = $this->isSanitized($node->expr);
            }
        }
    }

    private function trackUserInputAssignment(Node\Expr\Assign $node)
    {
        if ($node->expr instanceof ArrayDimFetch && 
            ($node->expr->var instanceof Variable && 
            in_array($node->expr->var->name, ['_GET', '_REQUEST'], true))) {
            // If the variable is assigned from $_GET or $_REQUEST, mark it as user input
            $varName = $node->var->name;
            $this->variables[$varName] = false; // Mark as unsafe by default
        } elseif ($node->expr instanceof Variable) {  
            // If it's just a regular assignment between variables, mark it as safe
            $varName = $node->var->name;
            $this->variables[$varName] = true; // This is a safe assignment (not user input)
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
            $safeFunctions = ['abs', 'intval', 'floatval', 'esc_html', 'esc_attr'];

            return in_array($functionName, $safeFunctions, true);
        }

        return false; // Default to unsafe
    }
}
