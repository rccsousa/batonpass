using BatonPass.Windows.Agent.Crypto;

namespace BatonPass.Windows.Agent.State;

/// Dedup key per SPEC.md §5: (key_epoch, sender_id, event_id).
public readonly record struct DedupKey(uint Epoch, uint SenderId, EventId EventId);
