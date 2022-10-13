# juju-controller

## Description

The Juju controller charm allows charms to interact with the Juju controller
via integrations. This charm is automatically deployed in the `controller`
model of every controller for Juju 3.0 or later.

## Usage

The controller charm currently supports integrations with
[`juju-dashboard`](https://charmhub.io/juju-dashboard) and
[`haproxy`](https://charmhub.io/haproxy).

You can deploy the Juju Dashboard in the `controller` model:
```console
$ juju switch controller
$ juju deploy juju-dashboard --channel beta
$ juju integrate controller juju-dashboard
```

or you can deploy it in its own model, and connect to the controller charm via
a cross-model integration:
```console
$ juju add-model dashboard
$ juju deploy juju-dashboard --channel beta
$ juju offer juju-dashboard:controller
Application "juju-dashboard" endpoints [controller] available at "admin/dashboard.juju-dashboard"
$ juju switch controller
$ juju integrate controller admin/dashboard.juju-dashboard
```

Then, run
```
juju dashboard --browser
```
and log in using the printed credentials.
