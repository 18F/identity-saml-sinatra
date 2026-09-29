# frozen_string_literal: true

require 'date'
require 'digest'

# Obviously fictional benefits records for the demo API, keyed by the
# assertion's NameID (the user's pairwise identifier for this agency).
# Nothing here is real data; records are generated from a hash of the NameID
# and kept in memory only for the life of the process.
class DemoBenefits
  PROGRAMS = [
    'Example Heating Assistance (fictional)',
    'Example Housing Voucher (fictional)',
    'Example Nutrition Support (fictional)',
  ].freeze

  # Fields POST /api/benefits may change.
  EDITABLE_FIELDS = %w[mailing_address preferred_contact].freeze

  class InvalidChange < StandardError; end

  def initialize
    @records = {}
    @mutex = Mutex.new
  end

  # @return [Hash] the record for this NameID, seeded on first use
  def record_for(name_id)
    @mutex.synchronize { @records[name_id] ||= seed(name_id) }
  end

  # Apply a change made through delegated access. The record remembers which
  # service provider (actor) made it and under which delegation_id.
  #
  # @param changes [Hash] JSON body of the POST; only EDITABLE_FIELDS accepted
  # @return [Hash] the updated record
  def update(name_id, changes, actor:, delegation_id:)
    unless changes.is_a?(Hash) && !changes.empty?
      raise InvalidChange.new('request body must be a JSON object with at least one field')
    end

    unknown = changes.keys - EDITABLE_FIELDS
    unless unknown.empty?
      raise InvalidChange.new(
        "unknown field(s) #{unknown.join(', ')}; editable: #{EDITABLE_FIELDS.join(', ')}",
      )
    end

    @mutex.synchronize do
      record = (@records[name_id] ||= seed(name_id))
      changes.each { |field, value| record[field] = value }
      record['last_updated'] = {
        'at' => Time.now.utc.iso8601,
        'by_actor' => actor,
        'delegation_id' => delegation_id,
      }
      record
    end
  end

  def clear
    @mutex.synchronize { @records.clear }
  end

  private

  def seed(name_id)
    digest = Digest::SHA256.hexdigest(name_id.to_s)
    n = digest[0, 8].to_i(16)
    {
      'case_number' => "DEMO-#{digest[0, 8].upcase}",
      'program' => PROGRAMS[n % PROGRAMS.size],
      'status' => 'active (fictional)',
      'monthly_amount_usd' => 100 + (n % 400),
      'next_payment_date' => (Date.today + 14).iso8601,
      'mailing_address' => {
        'street' => "#{100 + (n % 899)} Example Street",
        'city' => 'Anytown',
        'state' => 'XX',
        'zip' => '00000',
      },
      'preferred_contact' => 'mail',
      'last_updated' => nil,
    }
  end
end
