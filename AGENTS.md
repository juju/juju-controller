# juju-controller Agent Rules Index

Ensure that the following documents have been read:

 - [Juju Hook Lifecycle](https://documentation.ubuntu.com/juju/3.6/reference/hook/)
 - [Operator Framework](https://documentation.ubuntu.com/ops/latest/reference/)

If guidance conflicts, Juju Hook Lifecycle rules take precedence.

## Setup

Install `astral-uv` using snaps:

```
sudo snap install astral-uv --classic
```

You also need `make` to run local development tasks (format/lint/unit/integration).

## Local development

To see available make targets:
```
make help
```

To quickly run all quality checks

```
make all
```

To run each check separately:

```
# Formatting
make format

# Linting
make lint

# Running unit tests
make unit
```

## Build

Install `charmcraft` using snaps:

```
sudo snap install charmcraft --classic
```

Then run charmcraft pack:

```
charmcraft pack -v
```

## Updating libs

```
charmcraft fetch-libs
```
