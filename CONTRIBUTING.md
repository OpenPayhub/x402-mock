# Contributing to x402-mock

Thank you for your interest in contributing to x402-mock! We genuinely appreciate any help, whether it's fixing typos, reporting bugs, improving documentation, or adding new features.

## We Welcome All Contributions

This project is far from perfect, and we know there's always room for improvement. Whether you think the code could be better, you've found a bug, or you have an exciting new idea, we'd love to hear from you! All contributions, big or small, are valued and appreciated.

## Ways to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub with:
- A clear description of the problem
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment details (Python version, OS, etc.)

### Suggesting Features

Have an idea for a new feature or improvement? We'd love to hear it! Please open an issue to discuss:
- What problem does it solve?
- How would it work?
- Any implementation ideas you have

### Contributing Code

We appreciate code contributions! Whether it's fixing bugs, improving performance, or adding features, your help makes this project better.

## Development Setup

We use [uv](https://github.com/astral-sh/uv) for dependency management and development. Here's how to get started:

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR-USERNAME/x402-mock.git
cd x402-mock
```

### 2. Install uv

If you haven't installed uv yet, please visit [uv installation guide](https://github.com/astral-sh/uv).

### 3. Set Up Development Environment

```bash
# Sync dependencies and install development tools
uv sync --extra dev
```

## Development Workflow

### 1. Create a Branch

Always create a new branch for your changes:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Your Changes

- Write clear, readable code
- Add tests for new features
- Update documentation as needed
- Follow the existing code style

### 3. Run Tests

```bash
# Run tests with pytest
uv run pytest

# Run tests with coverage
uv run pytest --cov=src/x402_mock --cov-report=html
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "Brief description of your changes"
```

Write clear commit messages that explain what changed and why.

### 5. Push and Create a Pull Request

```bash
git push origin feature/your-feature-name
```

Then go to the [repository](https://github.com/OpenPayhub/x402-mock) and create a Pull Request.

## Pull Request Guidelines

- **One PR per feature/fix**: Keep PRs focused on a single change
- **Clear description**: Explain what your PR does and why
- **Reference issues**: Link to related issues if applicable
- **Tests**: Include tests for new functionality
- **Documentation**: Update docs if you're changing behavior
- **Be patient**: We'll review as soon as we can and may suggest changes

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to public functions and classes
- Keep functions focused and reasonably sized
- Comment complex logic

## Running the Examples

Test your changes with the provided examples:

```bash
# Run the server example
uv run example/server_example.py

# Run the client example (in another terminal)
uv run example/client_example.py
```

## Need Help?

If you have questions or need help with anything:

- Open an issue on GitHub for questions about the project
- Email us at **xxmuyou78@gmail.com** for other inquiries

## Code of Conduct

Please be respectful and constructive in all interactions. We're all here to learn and improve together.

## Thank You!

Your contributions help make x402-mock better for everyone. We're grateful for your time and effort, regardless of whether your contribution is merged, and we promise to provide thoughtful feedback on all submissions.

Happy coding! 🚀
