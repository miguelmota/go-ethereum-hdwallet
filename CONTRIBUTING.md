# Contributing to go-ethereum-hdwallet

First off, thank you for considering contributing to go-ethereum-hdwallet! It's people like you that make this project better.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include Go version (`go version`)
* Include your environment details

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* Use a clear and descriptive title
* Provide a step-by-step description of the suggested enhancement
* Provide specific examples to demonstrate the steps
* Describe the current behavior and explain which behavior you expected to see instead
* Explain why this enhancement would be useful
* List some other wallets or projects where this enhancement exists

### Pull Requests

* Fork the repo and create your branch from `master`
* If you've added code that should be tested, add tests
* Ensure the test suite passes (`make test`)
* Make sure your code follows the existing code style
* Write a convincing description of your PR and why we should land it

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/go-ethereum-hdwallet.git`
3. Create your feature branch: `git checkout -b feature/my-new-feature`
4. Make your changes
5. Run the tests: `make test`
6. Commit your changes: `git commit -am 'Add some feature'`
7. Push to the branch: `git push origin feature/my-new-feature`
8. Submit a pull request

### Running Tests

```bash
make test
```

### Coding Style

* Use `gofmt` to format your code
* Follow Go best practices and idioms
* Write descriptive commit messages
* Add comments for complex logic
* Update documentation when changing functionality

## Project Structure

```
.
├── cmd/                    # Command line tools
│   └── geth-hdwallet/     # CLI tool for wallet operations
├── examples/              # Example code and usage
├── vendor/               # Vendored dependencies
├── *.go                  # Core wallet implementation
├── go.mod               # Go module definition
├── go.sum               # Go module checksums
└── README.md            # Project documentation
```

## Testing

* Write unit tests for new code
* Ensure all tests pass before submitting PR
* Test edge cases and error conditions
* Add integration tests for new features
* Test against different Go versions

### Test Coverage

We strive to maintain high test coverage. When adding new code:

* Add unit tests for new functions
* Test both success and failure paths
* Test edge cases
* Run `go test -cover` to check coverage

## Documentation

* Update README.md for user-facing changes
* Add godoc comments to exported functions
* Include examples for new features
* Keep documentation up to date with code changes

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create a new release on GitHub
4. Tag the release
5. Update documentation

## Getting Help

* Create an issue for bugs
* Join discussions in existing issues
* Reach out to maintainers if stuck

## License

By contributing, you agree that your contributions will be licensed under the MIT License. 