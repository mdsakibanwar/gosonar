#!/bin/bash

# Function to display ASCII artwork of a gopher holding a radar gun
print_gosonar() {
    cat << "EOF"
░█▀▀░█▀█░█▀▀░█▀█░█▀█░█▀█░█▀▄
░█░█░█░█░▀▀█░█░█░█░█░█▀█░█▀▄
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀
EOF
    
}

# Main logic
if [[ $# -eq 0 ]]; then
    # No arguments provided, run benchmark mode
    print_gosonar
    echo "Running benchmark..."
    for i in bins/benchmark/*; do
        if [[ -f "$i" ]]; then
            python src/main.py --worker-type benchmark --binary "$i"
        fi
    done
elif [[ $# -ge 1 ]]; then
    print_gosonar
    echo "Running analysis for package $1..."
    # First argument is treated as a package
    PACKAGE=$1
    MODE=${2:-""} # Second argument can be empty or "call"

    if [[ "$MODE" == "call" ]]; then
        python src/main.py --worker-type loop-finder --package "$PACKAGE" --mode call-resolver
        echo "Completed loop-finder with call-resolver mode for package $PACKAGE."
        python src/main.py --worker-type stem-finder --package "$PACKAGE" --mode call-resolver
        echo "Completed stem-finder with call-resolver mode for package $PACKAGE."
        python src/main.py --worker-type lasso-verifier --package "$PACKAGE" --mode call-resolver
        echo "Completed lasso-verifier with call-resolver mode for package $PACKAGE."
    else
        python src/main.py --worker-type loop-finder --package "$PACKAGE"
        echo "Completed loop-finder for package $PACKAGE."
        python src/main.py --worker-type stem-finder --package "$PACKAGE"
        echo "Completed stem-finder for package $PACKAGE."
        python src/main.py --worker-type lasso-verifier --package "$PACKAGE"
        echo "Completed lasso-verifier for package $PACKAGE."
    fi
else
    echo "Invalid arguments provided."
    exit 1
fi