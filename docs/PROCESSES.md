# Process Containers

The process layer binds three previously independent security mechanisms into one lifecycle:

- a private capability domain,
- a private lower-half address space with shared kernel mappings, and
- a typed process control capability held by a manager.

The prototype supports 16 process records. Creation is transactional: partial address spaces,
domains, and objects are rolled back on failure. Process identifiers and slot generations are
separate, so slot reuse cannot make a stale handle current.

Inspection and administration are distinct rights. Termination is an explicit `ready -> exited`
transition and destruction is refused until the process has exited. Destruction tears down the
address space, capability domain, and registered process object before the slot can be reused.

ELF loading, threads, user-mode entry, and asynchronous exit notification remain later layers.
