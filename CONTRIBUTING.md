# Contributing to cfdiag

First off, thanks for taking the time to contribute!

## Development Setup

1.  **Clone the repo:**
    ```bash
    git clone https://github.com/baturkacamak/cfdiag.git
    cd cfdiag
    ```

2.  **Install Pre-commit Hook:**
    This ensures tests run automatically before you commit anything.
    ```bash
    ./setup_dev.sh
    ```

## Workflow

1.  Create a new branch (`git checkout -b feature/amazing-feature`).
2.  Make your changes.
3.  **Run Tests:**
    ```bash
    ./scripts/run_tests.sh
    ```
4.  Commit your changes (`git commit -m 'Feat: Add some AmazingFeature'`).
5.  Push to the branch (`git push origin feature/amazing-feature`).
6.  Open a Pull Request.

## Coding Standards

*   **Type Hinting:** Please use Python type hints (`def func(a: str) -> bool:`) for all new functions.
*   **No Dependencies:** Do NOT import external libraries (like `requests`, `colorama`). Stick to the standard library (`socket`, `urllib`, `ssl`, etc.) to keep the tool portable.
*   **Cross-Platform:** Ensure your changes work on Linux, macOS, and Windows. Use `os.name == 'nt'` checks if necessary.

## Testing

Add a test case in `test_cfdiag.py` for any new logic. We use `unittest` and `unittest.mock`.
