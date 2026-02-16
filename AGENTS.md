# Instructions for Coding Agents

## Context

You can find relevant information about this project in the following files:

- [README.md](README.md): General project overview and usage instructions.
- [Design.md](docs/Design.md): Detailed design decisions and architecture.

## Language

You **must** use English as the primary language for all code, comments, 
and documentation.

## Commands

- Always make sure to run `go mod tidy` after adding new dependencies
- Use `go run main.go` to run the application locally. 
  Prefer this over `make run`
- Use `make test` to run all tests with coverage
- Use `make lint` to check code quality with `golangci-lint`
- Use `make fmt` to format the code
- Use `make vet` to check for common mistakes
- Use `make coverage` to generate a coverage report
- Use `make vendor` to vendor dependencies
- Use `make logs` to view application logs
- Use `make up` to start the application in the background
- Use `make down` to stop and remove all containers
- Use `make fix` to run `go fix` on the codebase

## Completing Tasks

Your task is considered complete when:

- All tests pass
- Code is properly formatted
- Code is linted
- Code is vetted
- Code is documented
- Documentation is updated

## General Philosophy

- Do things the Go way
- Keep it simple
- Write idiomatic Go code
- Focus on readability and maintainability
- Use standard libraries where possible
- Avoid unnecessary complexity
- Document your code well...
- ... but do not add unnecessary comments
- Use meaningful variable and function names
- Write tests for all new features
- Use interfaces to decouple components
- Use context for cancellation and timeouts
- Use existing code if it fits the purpose
- Have a look at the existing codebase to 
  understand the project structure and conventions

## Code Style Guidelines

- **Imports**: Use goimports formatting, group stdlib, external, internal packages
- **Naming**: Standard Go conventions - `PascalCase` for exported, `camelCase` for unexported
- **Types**: Prefer explicit types, use type aliases for clarity (e.g., `type AgentName string`)
- **Error handling**: Return errors explicitly, use `fmt.Errorf` for wrapping
- **Context**: Always pass `context.Context` as first parameter for operations
- **Interfaces**: Define interfaces in consuming packages, keep them small and focused
- **Structs**: Use struct embedding for composition, group related fields
- **Constants**: Use typed constants with iota for enums, group in const blocks
- **JSON tags**: Use `snake_case` for JSON field names
- **File permissions**: Use octal notation (`0o755`, `0o644`) for file permissions