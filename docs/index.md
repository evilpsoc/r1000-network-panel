# LocalPlane Docs

LocalPlane is moving toward a small Linux edge-device control plane: observe
the host, explain the current state, preview changes, apply only owned changes,
verify the result, and keep enough history to recover.

These docs are intentionally practical. They describe how the project should be
operated and how new features should be designed.

## Guides

- [Operator Guide](guide.md)
- [Networking Model](networking.md)
- [Configuration Reference](configuration.md)
- [Security Notes](security.md)
- [Development Backlog](development-backlog.md)

## Product Principles

- Keep the core generic Linux first; device profiles add hardware-specific
  behavior.
- Make optional features capability-driven instead of assuming every host has
  every dependency.
- Prefer read-only inventory and analysis before adding hard apply flows.
- Route/firewall/Wi-Fi/cellular changes must use preview, apply, verify and
  rollback language.
- UI pages should stay compact by default and expand into deeper panels only
  when the operator asks.
