# sbx

|          |                                    |
| -------- | ---------------------------------- |
| Description | Manage AI coding agent sandboxes. |
| Usage    | `sbx`                              |

## Description

Docker Sandboxes creates isolated sandbox environments for AI agents, powered by Docker.

Run without a command to launch interactive mode, or pass a command for CLI usage.

## Commands

| Command        | Description                                    |
| -------------- | ---------------------------------------------- |
| `sbx completion` | Generate the autocompletion script for the specified shell |
| `sbx create`   | Create a sandbox for an agent                  |
| `sbx exec`     | Execute a command inside a sandbox             |
| `sbx login`    | Sign in to Docker                              |
| `sbx logout`   | Sign out of Docker                             |
| `sbx ls`       | List sandboxes                                 |
| `sbx policy`   | Manage sandbox policies                        |
| `sbx ports`    | Manage sandbox port publishing                 |
| `sbx reset`    | Reset all sandboxes and clean up state         |
| `sbx rm`       | Remove one or more sandboxes                   |
| `sbx run`      | Run an agent in a sandbox                      |
| `sbx save`     | Save a snapshot of the sandbox as a template   |
| `sbx secret`   | Manage stored secrets                          |
| `sbx stop`     | Stop one or more sandboxes without removing them |
| `sbx version`  | Show Docker Sandboxes version information      |

## Options

| Option       | Default | Description          |
| ------------ | ------- | -------------------- |
| `-D, --debug` |         | Enable debug logging |
