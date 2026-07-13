# skillguard report — /private/tmp/skillguard-corpus/SawyerHood__dev-browser

- Artifact type: marketplace
- Content hash: sha256:e29a0b10b45d80b041a71518d8112c73a8a3216d733d31c75eef4902f807a056
- Scanned at: 2026-07-13T14:05:33.451Z (skillguard v0.1.0, report v1)
- Files scanned: 170

**11 finding(s): 0 critical, 10 warning, 1 info**

- [WARNING] structural/no-skills — artifact contains no skills (.)
- [WARNING] capability/network-call — bundled script makes a network call (daemon/src/browser-manager.ts:682)
- [WARNING] capability/write-outside-artifact — bundled script writes to an absolute or home path outside the artifact directory (daemon/src/browser-manager.ts:818)
- [WARNING] capability/network-call — bundled script makes a network call (daemon/src/daemon.ts:392)
- [WARNING] capability/network-call — bundled script makes a network call (daemon/src/sandbox/__tests__/sandbox-security.test.ts:87)
- [WARNING] capability/write-outside-artifact — bundled script writes to an absolute or home path outside the artifact directory (daemon/src/sandbox/forked-client/src/client/domCuaInjected.ts:93)
- [WARNING] capability/network-call — bundled script makes a network call (daemon/src/sandbox/forked-client/src/client/network.ts:366)
- [WARNING] capability/write-outside-artifact — bundled script writes to an absolute or home path outside the artifact directory (daemon/src/sandbox/forked-client/src/utils/isomorphic/stringUtils.ts:110)
- [WARNING] capability/network-call — bundled script makes a network call (daemon/src/sandbox/forked-client/types/protocol.d.ts:878)
- [WARNING] capability/network-call — bundled script makes a network call (daemon/src/sandbox/forked-client/types/types.d.ts:19130)
- [INFO] supplychain/binary-file — bundled binary media file (.png) (assets/header.png)

_Static analysis only — behavioral verification (M1) requires sandboxed execution and is out of scope for this report._
