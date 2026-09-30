require 'digest'

module Digest
  #
  # Base class for all CRC algorithms.
  #
  class CRC < Digest::Class

    include Digest::Instance

    #
    # Raised when a CRC state transition cannot be uniquely reversed.
    #
    class NonInvertibleError < StandardError; end

    # The initial value of the CRC checksum
    INIT_CRC = 0x00

    # The XOR mask to apply to the resulting CRC checksum
    XOR_MASK = 0x00

    # The bit width of the CRC checksum
    WIDTH = 0

    # Define true or false whether the input direction is bit reversed or not of the CRC checksum
    REFLECT_INPUT = nil

    # Default place holder CRC table
    TABLE = [].freeze

    #
    # Calculates the CRC checksum.
    #
    # @param [String] data
    #   The given data.
    #
    # @return [Integer]
    #   The CRC checksum.
    #
    def self.checksum(data)
      crc = self.new
      crc << data

      return crc.checksum
    end

    #
    # Packs the given CRC checksum.
    #
    # @param [Integer] crc
    #   The raw CRC checksum.
    #
    # @return [String]
    #   The packed CRC checksum.
    #
    def self.pack(crc)
      unless (width = self::WIDTH) > 0
        raise(NotImplementedError, "#{self} is incompleted as CRC")
      end

      bitclass   = width + (-width & 0x07)
      byte_count = bitclass / 8

      crc &= ~(-1 << width)

      result = [crc].pack("Q>")
      result[0, result.bytesize - byte_count] = ""
      result
    end

    #
    # Determines whether the library is using the optimized C extensions
    # implementation, or the pure-Ruby implementation.
    #
    # @return [:c_ext, :pure]
    #
    # @since 0.7.0
    #
    def self.implementation
      if instance_method(:update).source_location.nil?
        :c_ext
      else
        :pure
      end
    end

    #
    # Combines the checksums of two contiguous sequences of bytes.
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
    # @since 0.7.0
    #
    def self.combine(crc1,crc2,length2)
      width  = validated_width
      matrix = crc_matrix
      power  = matrix_power(matrix,validated_length(length2))

      xor_mask = const_value(:XOR_MASK,width)
      raw1 = normalized_value(crc1,width) ^ xor_mask
      raw2 = normalized_value(crc2,width) ^ xor_mask
      zero = const_value(:INIT_CRC,width)

      raw = apply_matrix(power,raw1) ^ raw2 ^ apply_matrix(power,zero)

      return raw ^ xor_mask
    end

    #
    # Recovers one checksum from the checksum of two concatenated sequences.
    #
    # By default the first checksum is recovered, as it is when reversing a
    # {combine} call. Pass `missing: :second` to recover the second checksum.
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
    # @raise [NonInvertibleError]
    #   The state transition cannot be uniquely reversed.
    #
    # @since 0.7.0
    #
    def self.uncombine(combined_crc,known_crc,second_length,missing: :first)
      unless missing == :first || missing == :second
        raise(ArgumentError,"missing must be :first or :second")
      end

      width  = validated_width
      length = validated_length(second_length)
      matrix = crc_matrix
      power  = matrix_power(matrix,length)
      xor    = const_value(:XOR_MASK,width)

      combined = normalized_value(combined_crc,width) ^ xor
      known    = normalized_value(known_crc,width) ^ xor
      zero     = const_value(:INIT_CRC,width)

      if missing == :first
        if length == 0
          raw = combined
        else
          inverse = matrix_power(inverse_matrix(matrix),length)
          value = combined ^ known ^ apply_matrix(power,zero)
          raw = apply_matrix(inverse,value)
        end
      else
        if length == 0
          raw = zero
        else
          raw = combined ^ apply_matrix(power,known) ^ apply_matrix(power,zero)
        end
      end

      return raw ^ xor
    end

    class << self
      private

      def validated_width
        width = const_get(:WIDTH)

        unless width.is_a?(Integer) && width >= 1
          raise(NotImplementedError,"incompleted #{self} as CRC (expected WIDTH to be 1 or more)")
        end

        return width
      end

      def validated_length(length)
        length = length.to_int if !length.is_a?(Integer) && length.respond_to?(:to_int)

        unless length.is_a?(Integer) && length >= 0
          raise(ArgumentError,"length must be a non-negative Integer")
        end

        return length
      end

      def normalized_value(value,width)
        value = value.to_int if !value.is_a?(Integer) && value.respond_to?(:to_int)

        unless value.is_a?(Integer) && value >= 0 && value <= ((1 << width) - 1)
          raise(ArgumentError,"CRC value must be between 0 and #{(1 << width) - 1}")
        end

        return value
      end

      def const_value(name,width)
        value = const_get(name)
        value = value.to_int if !value.is_a?(Integer) && value.respond_to?(:to_int)

        unless value.is_a?(Integer) && value >= 0 && value <= ((1 << width) - 1)
          raise(NotImplementedError,"incompleted #{self} as CRC (#{name} must fit within #{width} bits)")
        end

        return value
      end

      def crc_matrix
        @crc_matrix ||= begin
          width         = validated_width
          table         = const_get(:TABLE)
          reflect_input = const_get(:REFLECT_INPUT)
          mask          = (1 << width) - 1

          unless table.is_a?(Array) && table.size == 256
            raise(NotImplementedError,"incompleted #{self} as CRC (expected TABLE to contain 256 entries)")
          end

          if reflect_input.nil?
            raise(NotImplementedError,"incompleted #{self} as CRC (expected REFLECT_INPUT to be not nil)")
          end

          Array.new(width) do |bit|
            input = 1 << bit
            index = if reflect_input
                      input & 0xff
                    elsif width > 8
                      (input >> (width - 8)) & 0xff
                    else
                      (input << (8 - width)) & 0xff
                    end

            column = table.fetch(index) & mask

            if width > 8
              if reflect_input && bit >= 8
                column = 1 << (bit - 8)
              elsif !reflect_input && bit < (width - 8)
                column = 1 << (bit + 8)
              end
            end

            column
          end
        end
      end

      def apply_matrix(matrix,value)
        result = 0
        column = 0

        while value != 0
          result ^= matrix[column] unless (value & 1).zero?
          value >>= 1
          column += 1
        end

        return result
      end

      def multiply_matrix(left,right)
        right.map { |column| apply_matrix(left,column) }
      end

      def matrix_power(matrix,power)
        result = Array.new(matrix.size) { |bit| 1 << bit }

        while power > 0
          result = multiply_matrix(matrix,result) unless (power & 1).zero?
          matrix = multiply_matrix(matrix,matrix)
          power >>= 1
        end

        return result
      end

      def inverse_matrix(matrix)
        width    = matrix.size
        rows     = Array.new(width,0)

        matrix.each_with_index do |column,column_index|
          width.times do |row_index|
            rows[row_index] |= 1 << column_index unless (column & (1 << row_index)).zero?
          end

          rows[column_index] |= 1 << (width + column_index)
        end

        width.times do |pivot|
          pivot_row = pivot.upto(width - 1).find { |row| !((rows[row] >> pivot) & 1).zero? }

          unless pivot_row
            raise(NonInvertibleError,"#{self} CRC transition is not uniquely reversible")
          end

          rows[pivot],rows[pivot_row] = rows[pivot_row],rows[pivot] if pivot_row != pivot

          width.times do |row|
            next if row == pivot || ((rows[row] >> pivot) & 1).zero?

            rows[row] ^= rows[pivot]
          end
        end

        return Array.new(width) do |column|
          value = 0

          width.times do |row|
            value |= 1 << row unless (rows[row] & (1 << (width + column))).zero?
          end

          value
        end
      end
    end

    #
    # Initializes the CRC checksum.
    #
    def initialize
      @init_crc      = self.class.const_get(:INIT_CRC)
      @xor_mask      = self.class.const_get(:XOR_MASK)
      @width         = self.class.const_get(:WIDTH)
      @reflect_input = self.class.const_get(:REFLECT_INPUT)
      @table         = self.class.const_get(:TABLE)

      reset
    end

    #
    # The input block length.
    #
    # @return [1]
    #
    def block_length
      1
    end

    #
    # The length of the digest.
    #
    # @return [Integer]
    #   The length in bytes.
    #
    def digest_length
      (@width / 8.0).ceil
    end

    #
    # Updates the CRC checksum with the given data.
    #
    # @param [String] data
    #   The data to update the CRC checksum with.
    #
    # @raise [NotImplementedError]
    #   If WIDTH, TABLE, or REFLECT_INPUT constants are not set properly.
    #
    def update(data)
      unless @width >= 1
        raise(NotImplementedError, "incompleted #{self.class} as CRC (expected WIDTH to be 1 or more)")
      end

      if @table.empty?
        raise(NotImplementedError, "incompleted #{self.class} as CRC (expected TABLE to be not empty)")
      end

      if @reflect_input.nil?
        raise(NotImplementedError, "incompleted #{self.class} as CRC (expected REFLECT_INPUT to be not nil)")
      end

      table = @table
      crc   = @crc

      if @reflect_input
        if @width > 8
          data.each_byte do |b|
            crc = table[b ^ (0xff & crc)] ^ (crc >> 8)
          end
        else
          data.each_byte do |b|
            # Omit (crc >> 8) since bits upper than the lower 8 bits are always 0
            crc = table[b ^ (0xff & crc)]
          end
        end
      else
        if @width > 8
          higher_bit_off = @width - 8
          remain_mask    = ~(-1 << higher_bit_off)

          data.each_byte do |b|
            crc = table[b ^ (0xff & (crc >> higher_bit_off))] ^ ((remain_mask & crc) << 8)
          end
        else
          padding = 8 - @width

          data.each_byte do |b|
            # Omit (crc << 8) since bits lower than the upper 8 bits are always 0
            crc = table[b ^ (0xff & (crc << padding))]
          end
        end
      end

      @crc = crc

      self
    end

    #
    # @see #update
    #
    def <<(data)
      update(data)
      return self
    end

    #
    # Resets the CRC checksum.
    #
    # @return [Integer]
    #   The default value of the CRC checksum.
    #
    def reset
      @crc = @init_crc
    end

    #
    # The resulting CRC checksum.
    #
    # @return [Integer]
    #   The resulting CRC checksum.
    #
    def checksum
      @crc ^ @xor_mask
    end

    #
    # Finishes the CRC checksum calculation.
    #
    # @see pack
    #
    def finish
      self.class.pack(checksum)
    end

  end
end
