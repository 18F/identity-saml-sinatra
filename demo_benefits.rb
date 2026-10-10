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

  def initialize
    @records = {}
    @mutex = Mutex.new
  end

  # @return [Hash] the record for this NameID, seeded on first use
  def record_for(name_id)
    @mutex.synchronize { @records[name_id] ||= seed(name_id) }
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
    }
  end
end
