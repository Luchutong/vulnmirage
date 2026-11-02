# Evidence-check prompt

For every security-relevant claim you accept or reject, record the concrete
evidence that supports the decision:

- the exact file and line range you inspected, quoted or cited;
- the call chain from an external entry point to the critical operation;
- the protection mechanism you checked (parameter binding, encoding,
  authorization check, allow-list, framework guard) and where it is applied;
- if you ran a command, its exit status and the relevant output.

A claim is only resolved when the cited evidence is sufficient to distinguish
the vulnerable path from the safe one. If the evidence is incomplete, say which
check is missing instead of assuming safety or vulnerability. This is a prompt
level verification policy: it does not grant access to hidden ground truth,
oracle records, proofs or answer keys, and it does not enforce a runtime gate.
