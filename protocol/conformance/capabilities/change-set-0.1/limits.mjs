// A Change Set may prove opaque large-file behavior with durable filesystem
// writes. Hosted macOS runners can take more than 30 seconds to fsync that
// scenario even when the implementation is healthy, so the portable default
// leaves explicit headroom while retaining a finite hard ceiling.
export const DEFAULT_COMMAND_TIMEOUT_MS = 90_000;
export const MAXIMUM_COMMAND_TIMEOUT_MS = 300_000;
