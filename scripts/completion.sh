#!/bin/bash
# CyberSecurity Suite - Bash Completion
# Tab completion for suite commands

_suite_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    opts="scan report update setup health help"
    
    # Subcommands
    case "${COMP_WORDS[1]}" in
        scan)
            opts="--quick --full --targets --output"
            ;;
        report)
            opts="--type --format --output --name"
            ;;
        update)
            opts="--databases --system --python"
            ;;
    esac
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _suite_completion suite.sh
complete -F _suite_completion cyberscan