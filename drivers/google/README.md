# Argus Google drivers

Gmail and Google Drive drivers for Argus integration scenarios that test an
agent through its existing mail and document connectors. Gmail prepares and
observes marked messages, including seed delivery; Drive prepares and observes
marked documents. Both drivers clean objects owned by the scenario run.

Install the driver at the same version as argus-probe:

```bash
pip install argus-drivers-google==<version>
```

The package requires argus-probe 1.15.1 or later and registers `gmail` and
`gdrive` in the `argus.drivers` entry-point group. Configure a credential provider
and the scenario's connections before running a scenario.

See [integration scenarios](https://github.com/gy15901580825/Argus/blob/main/docs/integration-scenarios.md)
for installation from source, scenario configuration, permissions and cleanup
boundaries.
