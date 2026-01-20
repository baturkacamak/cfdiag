#!/bin/bash
echo "Running tests..."
python3 test_cfdiag.py
if [ $? -ne 0 ]; then
    echo "Tests failed! Aborting commit."
    exit 1
fi
echo "Tests passed."
exit 0
