# frozen_string_literal: true

# Remembers assertion IDs until the assertion can no longer be valid, so the
# same delegated assertion is accepted once.
#
# This is optional agency policy, not a Login.gov requirement. RFC 8693 §3 and
# SAML Core §2.5.1 do not forbid re-presenting a bearer assertion within its
# validity window, and the broker is expected to hold each assertion
# for up to five minutes and call the API more than once with it. An
# agency that wants one-call-per-assertion semantics keeps this enabled and
# tells its brokers to refresh before every call; one that expects
# repeat calls sets REPLAY_PROTECTION=false. Replay protection is the
# consumer-side control against a captured assertion being reused.
#
# In-memory and per process. A multi-instance deployment would back this with
# a shared store keyed the same way.
class AssertionReplayCache
  def initialize
    @seen = {}
    @mutex = Mutex.new
  end

  # @param assertion_id [String]
  # @param expires_at [Time] when the assertion is no longer valid (its
  #   NotOnOrAfter plus the accepted clock drift); the entry can be dropped then.
  # @return [Boolean] true if this is the first time the ID has been seen
  def first_use?(assertion_id, expires_at:)
    @mutex.synchronize do
      purge_expired
      return false if @seen.key?(assertion_id)

      @seen[assertion_id] = expires_at
      true
    end
  end

  def size
    @mutex.synchronize { @seen.size }
  end

  def clear
    @mutex.synchronize { @seen.clear }
  end

  private

  def purge_expired
    now = Time.now
    @seen.delete_if { |_id, expires_at| expires_at <= now }
  end
end
