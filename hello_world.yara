rule HelloWorld {
    meta:
        description = "Detects the presence of 'Hello, World!' string"
        author = "@knightchaser"
        version = "1.0"
    
    strings:
        $hello = "Hello, World!"
    
    condition:
        $hello
}

