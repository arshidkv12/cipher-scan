<?php

namespace SecurityChecker;

use PhpParser\NodeVisitor;

class NodeVisitorFactory
{
    public static function create($fileName, $functionDefinitions): array
    {
        return [
            new SQLInjectionDetector($fileName),
            // new XSSDetector($fileName),
            // new LFIDetector($fileName),
            new NonceCheckVisitor($fileName, $functionDefinitions),
            new FileUploadDetector(),
        ];
    }
}
