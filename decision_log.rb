# frozen_string_literal: true

# In-memory ring buffer of authorization decisions the API made, shown at
# GET /decisions and joined to Attempts API events on delegation_id in the
# Attempts viewer's "Delegated sessions" tab.
#
# Demo affordance: a real agency writes these to its audit log. Nothing here
# is required by the protocol.
class DecisionLog
  Entry = Struct.new(
    :time,               # Time the decision was made
    :route,              # e.g. "GET /api/benefits"
    :decision,           # "allow" or "deny"
    :reason,             # short text for denials (nil when allowed)
    :required_scope,     # the token_exchange:* value the route needs
    :name_id,            # Subject/NameID (pairwise identifier for this agency)
    :uuid,               # `uuid` attribute (same identifier the agency sees at direct sign-in)
    :actor,              # `actor` attribute: the service provider acting for the user
    :delegation_id,      # `delegation_id` attribute: joins to Attempts events
    :delegation_scopes,  # Array of approved token_exchange:* values
    :assertion_id,       # Assertion/@ID (what revocation and introspection key on)
    :key_bound,          # true when the assertion carried dpop_jkt (RFC 9449), so a DPoP
                         # proof was required; nil when the denial happened before that was known
    keyword_init: true,
  ) do
    def to_h
      super.transform_values { |v| v.is_a?(Time) ? v.utc.iso8601 : v }
    end
  end

  def initialize(max_size: 200)
    @max_size = max_size
    @entries = []
    @mutex = Mutex.new
  end

  # @return [Entry]
  def record(**fields)
    entry = Entry.new(time: Time.now.utc, **fields)
    @mutex.synchronize do
      @entries.push(entry)
      @entries.shift while @entries.size > @max_size
    end
    entry
  end

  # Newest first.
  # @return [Array<Entry>]
  def entries
    @mutex.synchronize { @entries.reverse }
  end

  # @return [Array<Entry>] decisions carrying the given delegation_id, newest first
  def for_delegation(delegation_id)
    return [] if delegation_id.nil?

    entries.select { |e| e.delegation_id == delegation_id }
  end

  def clear
    @mutex.synchronize { @entries.clear }
  end
end
