# Scan probe

This file exists to measure whether the repository's scan configuration is
honoured by GitGuardian's app. It carries the published WireGuard
key-conversion vector in the shape the app's generic high-entropy detector
reads as a credential:

```text
private_key=e8b4c7880338be0284822e6f9b7d1ffc40481161439b24a44dcf44582708a84b
```

The value is a published test vector. It belongs to no host and authenticates
nothing. If the scan reports it, the configuration on `main` is not honoured.
