# sbx exec

Execute a command inside a running sandbox.

## Usage

```bash
sbx exec [flags] SANDBOX COMMAND [ARG...]
```

## Description

Run a command inside a running sandbox container. This is similar to `docker exec` but works with sandbox names. You can use it to run interactive shells, start background processes, or execute one-off commands.

## Options

| Option | Description |
|--------|-------------|
| `-d, --detach` | Run in the background |
| `--detach-keys <string>` | Override the key sequence for detaching |
| `-e, --env <stringArray>` | Set environment variables |
| `--env-file <stringArray>` | Read environment variables from a file |
| `-i, --interactive` | Keep stdin open |
| `--privileged` | Give extended privileges to the command |
| `-t, --tty` | Allocate a pseudo-TTY |
| `-u, --user <string>` | Username or UID (format: `<name|uid>[:<group|gid>]`) |
| `-w, --workdir <string>` | Working directory inside the sandbox |

## Examples

```bash
# Open an interactive shell
sbx exec -it my-sandbox bash

# Run a command in the background
sbx exec -d my-sandbox npm start

# Run a command as root
sbx exec -u root my-sandbox apt-get update

# Set environment variables
sbx exec -e MY_VAR=hello my-sandbox printenv MY_VAR

# Run from a specific working directory
sbx exec -w /app my-sandbox ls
```
