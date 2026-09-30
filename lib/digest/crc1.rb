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

    #
    # Combines two CRC1 checksums.
    #
    # @param [Integer] crc1
    #   The checksum of the first sequence.
    #
    # @param [Integer] crc2
    #   The checksum of the second sequence.
    #
    # @param [Integer] length2
    #   The length, in bytes, of the second sequence.
    #
    # @return [Integer]
    #   The checksum of the concatenated sequences.
    #
    def self.combine(crc1,crc2,length2)
      validated_length(length2)

      unless crc1.is_a?(Integer) && crc1 >= 0 && crc1 <= 0xff &&
             crc2.is_a?(Integer) && crc2 >= 0 && crc2 <= 0xff
        raise(ArgumentError,"CRC value must be between 0 and 255")
      end

      return (crc1 + crc2) % 256
    end

    #
    # Recovers one CRC1 checksum from a combined checksum.
    #
    # @param [Integer] combined_crc
    #   The checksum of the concatenated sequences.
    #
    # @param [Integer] known_crc
    #   The checksum of the known sequence.
    #
    # @param [Integer] second_length
    #   The length, in bytes, of the second sequence.
    #
    # @param [:first, :second] missing
    #   Which checksum to recover.
    #
    # @return [Integer]
    #   The recovered checksum.
    #
    def self.uncombine(combined_crc,known_crc,second_length,missing: :first)
      unless missing == :first || missing == :second
        raise(ArgumentError,"missing must be :first or :second")
      end

      validated_length(second_length)

      unless combined_crc.is_a?(Integer) && combined_crc >= 0 && combined_crc <= 0xff &&
             known_crc.is_a?(Integer) && known_crc >= 0 && known_crc <= 0xff
        raise(ArgumentError,"CRC value must be between 0 and 255")
      end

      return (combined_crc - known_crc) % 256
    end

  end
end
