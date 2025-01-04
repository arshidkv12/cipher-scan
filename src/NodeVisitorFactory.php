<?php

namespace SecurityChecker;

use PhpParser\NodeVisitor;

class NodeVisitorFactory
{
    public static function create( $fileName ): array
    {
        return [
            new SQLInjectionDetector( $fileName ),
            new XSSDetector( $fileName ),
            new FileUploadDetector(),
        ];
    }
}
