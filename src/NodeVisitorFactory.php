<?php

namespace SecurityChecker;

use PhpParser\NodeVisitor;

class NodeVisitorFactory
{
    public static function create(): array
    {
        return [
            new SQLInjectionDetector(),
            new XSSDetector(),
            new FileUploadDetector(),
        ];
    }
}
