# Development guide

You will need to have Python 3, Charmcraft and [uv](https://docs.astral.sh/uv/) installed.
```
sudo snap install charmcraft --classic --channel latest/stable
sudo snap install astral-uv --classic
```

You also need `make` to run local development tasks.

## Local development tasks

Use `make` to run formatting, linting, and testing:

```console
$ make help
all             Run lint and unit tests (the default target)
help            Show this help
format          Format and auto-fix with ruff
lint            Lint with ruff, type-check with pyright, and check code spelling with codespell
unit            Run unit tests. To provide extra args, use: make unit ARGS='extra_args'
integration     Run integration tests
```

Run `make all` before you push and create a PR.

## Deploying

Before you deploy your modified controller charm, you will need to pack it using Charmcraft:
```console
$ charmcraft pack
...
Charms packed:
    juju-controller_[...].charm
```

If deploying on LXD, you can bootstrap Juju using the `--controller-charm-path` flag, and providing the path to your packed charm.
```console
$ juju bootstrap lxd c --controller-charm-path=[path/to/packed/charm]
```

If deploying on k8s, you need to upload the charm to Charmhub first. Register a new charm name for testing:
```console
$ charmcraft register [new-name]
```
and upload the modified charm under this name:
```console
$ charmcraft upload *.charm --name [new-name] --release latest/stable
Revision 1 of [new-name] created
Revision released to latest/stable
```

Then, you can bootstrap a new k8s controller, providing the Charmhub name and channel:
```console
$ juju bootstrap microk8s c \
--controller-charm-path=[new-name]
--controller-charm-channel=latest/stable
```

## Activate local virtualenv

The `make` commands doesn't need an activated virtualenv. If you
need to activate it for local development:

```
uv sync --frozen --group dev
source .venv/bin/activate
```

The `uv sync` command creates a local virtualenv for you.

## Releasing

To release a new version of the controller charm, first pack the charm as above:
```console
$ charmcraft pack
...
Charms packed:
    juju-controller_[...].charm
```

Then, upload under the name `juju-controller`:
```console
$ charmcraft upload *.charm --name juju-controller
Revision [XX] of 'juju-controller' created
```

Finally, release it to the relevant channels. Along with a `latest` track, we maintain a track for every minor version of Juju, e.g. `3.0`, `3.1`, etc.
```console
$ charmcraft release juju-controller --revision [XX] --channel latest/stable --channel 3.0/stable
Revision [XX] of charm 'juju-controller' released to latest/stable, 3.0/stable
```

You can also do the upload and release in a single step if you'd like:
```console
$ charmcraft upload *.charm --name juju-controller --release latest/stable --release 3.0/stable
Revision [XX] of 'juju-controller' created
Revision [XX] of charm 'juju-controller' released to latest/stable, 3.0/stable
```
