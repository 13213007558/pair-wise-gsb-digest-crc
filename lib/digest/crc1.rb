require 'digest/crc'

module Digest
  #
  # Implements the CRC1 algorithm.
  #
  class CRC1 < CRC

    WIDTH = 1

    #
    # Packs the CRC1 checksum.
    #
    # @return [String]
    #   The CRC1 checksum.
    #
    def self.pack(crc)
      [crc].pack('c*')
    end

    #
    # Updates the CRC1 checksum.
    #
    # @param [String] data
    #   The data to update the checksum with.
    #
    def update(data)
      accum = 0
      data.each_byte { |b| accum += b }

      @crc += (accum % 256)

      return self
    end

    def self.valid_patch_target?(target_checksum)
      target_checksum.is_a?(Integer) && target_checksum.between?(0, 255)
    end

    def self.patch_fallback(positions, data, baseline, target_checksum)
      return nil unless target_checksum.between?(0, 255)

      target_delta = (target_checksum - baseline) % 256
      solutions    = { 0 => 0 }

      positions.each_with_index do |(offset, bit), index|
        bit_value = 1 << bit
        old_bit   = (data.getbyte(offset) >> bit) & 1
        change    = old_bit.zero? ? bit_value : 256 - bit_value

        solutions.dup.each do |residue, selected|
          next_residue = (residue + change) % 256
          solutions[next_residue] ||= selected | (1 << index)
        end

        return solutions[target_delta] if solutions.key?(target_delta)
        break if solutions.size == 256
      end

      solutions[target_delta]
    end

    private_class_method :valid_patch_target?, :patch_fallback

  end
end
