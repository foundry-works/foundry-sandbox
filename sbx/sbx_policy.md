# sbx policy

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Manage persistent access policies for sandboxes. |
| Usage    | `sbx policy COMMAND`                         |

## Description

Manage persistent access policies for sandboxes.

## Commands

| Command                    | Description                                        |
| -------------------------- | -------------------------------------------------- |
| `sbx policy allow`         | Add a policy that permits access to resources      |
| `sbx policy deny`          | Add a policy that blocks access to resources       |
| `sbx policy log`           | Show policy log entries                            |
| `sbx policy ls`            | List active policies                               |
| `sbx policy reset`         | Remove all custom policies                         |
| `sbx policy rm`            | Remove a policy                                    |
| `sbx policy set-default`   | Set the default policy                             |

## Options

| Option       | Default | Description          |
| ------------ | ------- | -------------------- |
| `-D, --debug` |         | Enable debug logging |
