# juju-controller

## Description

The Juju controller hosts and manages Juju models.

## Usage

The controller provides an endpoint to integrate with a dashboard.

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Testing

The Python operator framework includes a very nice harness for testing
operator behaviour without full deployment. Just `run_tests`:

    ./run_tests
