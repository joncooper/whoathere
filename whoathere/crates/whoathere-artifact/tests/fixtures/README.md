# Inert artifact fixtures

These files model npm and PyPI archive structure for ordinary CI. They contain no restricted
samples, network destinations, credentials, obfuscation, or host-discovery behavior. Tests package
the source trees in memory and pass the resulting bytes to the non-extracting normalizer.

The npm lifecycle canary refuses to run unless an explicit inert-fixture environment gate and an
explicit output path are both present. Ordinary normalization tests inspect it as text and never
execute it.
