<?php

namespace SecurityChecker;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpParser\Node\Stmt\Echo_;
use PhpParser\Node\Expr\Print_;  // Correct way to handle print
use PhpParser\Node\Expr\Variable;

class XSSDetector extends NodeVisitorAbstract
{

    private $fileName;

    // Constructor to accept the file name
    public function __construct($fileName)
    {
        $this->fileName = $fileName;
    }

        
    public function enterNode(Node $node)
    { 
        // Check for echo statements
        if ($node instanceof Echo_) {
            $this->checkForEcho($node);
        }
        
        // Check for print statements
        if ($node instanceof Print_) {
            $this->checkForPrint($node);
        }
    }

    private function checkForEcho(Echo_ $node)
    {
        // Loop through expressions in echo
        foreach ($node->exprs as $expr) {
            // Check if the expression is a variable (could be user input)
            if ($expr instanceof Variable) {
                echo " XSS Risk detected - $this->fileName:{$node->getLine()}\n";
            }
        }
    }

    private function checkForPrint(Print_ $node)
    {
        // Check the expression being printed
        $expr = $node->expr;
        if ($expr instanceof Variable) {
            echo "XSS Risk detected - {$this->fileName}:{$node->getLine()} \n";
        }
    }
}

 
