# OpenDuck base bundle

`@openduck/openduck-base` is the deployment-neutral native DeepSeek Harness bundle. It registers the `openduckBase` Cordis service and the `openduck` namespace in DSH's native settings provider. Its default Controller state is disabled, and it never performs network access by itself.

Work-specific integrations belong in an external bundle such as `dsh-process`. Install that bundle into the profile with `dsh plugin --profile openduck add <package-or-path>`; its patch layer is then composed after this package. The base service exposes `settings()`, `status()`, `controller`, and `externalPackages()` for future adapters without embedding corporate URLs or credentials.
