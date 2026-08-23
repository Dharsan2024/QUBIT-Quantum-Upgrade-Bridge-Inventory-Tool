# T12_sonar_coverage_gate — Fifth-detector applicability gate (benchmarks/oracles/sonar_oracle.py)

sonar-cryptography reads Java, Python and Go. A repository is scanned only if it has >= 25 analysable files **and** they are >= 5% of it. Both halves are load-bearing: openwrt passes the count on 25 build scripts and fails the share, and scanning it would cost an hour to produce a guaranteed zero. A skip is recorded as 'cannot read', which is a different statement from 'found nothing'.

| repository | analysable | total files | share | >= files | >= share | verdict |
|---|---|---|---|---|---|---|
| RxJava | 2073 | 2184 | 94.9% | yes | yes | scan |
| TheAlgorithms/Python | 1385 | 1537 | 90.1% | yes | yes | scan |
| conductor | 1486 | 4171 | 35.6% | yes | yes | scan |
| CymChad (mixed Kotlin) | 25 | 263 | 9.5% | yes | yes | scan |
| openwrt (build scripts) | 25 | 11555 | 0.2% | yes | no | skip |
| redis (build scripts) | 48 | 1887 | 2.5% | yes | no | skip |
| libuv | 3 | 509 | 0.6% | no | no | skip |
| SwiftLint | 0 | 988 | 0.0% | no | no | skip |
