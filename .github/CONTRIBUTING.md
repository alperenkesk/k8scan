# Contributing to k8scan

Thank you for your interest in contributing to k8scan! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, k8s version)

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Describe the feature and use case
3. Explain why it would be valuable

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make your changes**:
   - Write clear, commented code
   - Follow existing code style
   - Add tests if applicable
4. **Test your changes**:
   ```bash
   python -m pytest tests/
   ```
5. **Commit** with clear messages:
   ```bash
   git commit -m "Add feature: description"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/my-feature
   ```
7. **Open a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/k8scan.git
cd k8scan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install pytest black flake8

# Run tests
pytest tests/
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings to functions and classes
- Keep functions focused and small

### Example:

```python
def scan_pods(pods: list) -> list:
    """
    Scan pods for security issues.
    
    Args:
        pods: List of pod objects from Kubernetes API
        
    Returns:
        List of Finding objects
    """
    findings = []
    # Implementation
    return findings
```

## Testing

- Write tests for new features
- Ensure existing tests pass
- Test with different Kubernetes versions if possible

## Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions/classes
- Update examples if behavior changes

## Adding New Security Checks

1. Create module in `src/modules/internal/`
2. Add exploit information in `src/exploits/`
3. Update exploit mapper
4. Add tests
5. Document the check

### Example Structure:

```python
# src/modules/internal/my_scanner.py
class MyScanner:
    def scan(self, resources):
        findings = []
        # Scan logic
        return findings

# src/exploits/my_exploits.py
class MyExploits:
    @staticmethod
    def my_vulnerability():
        return {
            'exploitation': [...],
            'attack_flow': [...],
            'impact': '...',
            'cvss_score': 8.5
        }
```

## Questions?

Feel free to open an issue for any questions about contributing!

Thank you for making k8scan better! 🚀
