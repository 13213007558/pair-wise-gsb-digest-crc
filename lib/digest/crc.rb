require 'digest'

module Digest
  #
  # Base class for all CRC algorithms.
  #
  class CRC < Digest::Class

    include Digest::Instance

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
    # Combines the CRC checksums of two consecutive chunks of data, without
    # having to re-read the first chunk.
    #
    # @example
    #   crc1 = Digest::CRC32.checksum(chunk1)
    #   crc2 = Digest::CRC32.checksum(chunk2)
    #   Digest::CRC32.combine(crc1, crc2, chunk2.bytesize) == Digest::CRC32.checksum(chunk1 + chunk2)
    #
    # @param [Integer] crc1
    #   The CRC checksum of the first chunk of data.
    #
    # @param [Integer] crc2
    #   The CRC checksum of the second chunk of data.
    #
    # @param [Integer] len2
    #   The length in bytes of the second chunk of data.
    #
    # @return [Integer]
    #   The CRC checksum of the concatenation of the two chunks.
    #
    # @raise [NotImplementedError]
    #   If WIDTH, TABLE, or REFLECT_INPUT constants are not set properly.
    #
    # @raise [ArgumentError]
    #   If the given length is not a non-negative Integer.
    #
    # @since 0.8.0
    #
    def self.combine(crc1, crc2, len2)
      width, init_crc, xor_mask = combine_parameters()
      crc_mask = (1 << width) - 1

      matrix = gf2_matrix_power(zero_byte_transition_matrix, combine_length(len2))

      state = (crc1 & crc_mask) ^ init_crc ^ xor_mask

      gf2_matrix_vector_mul(matrix, state) ^ (crc2 & crc_mask)
    end

    #
    # Recovers the CRC checksum of the first of two consecutive chunks of
    # data, given the CRC checksum of the concatenation and of the second
    # chunk.
    #
    # @example
    #   combined = Digest::CRC32.checksum(chunk1 + chunk2)
    #   crc2     = Digest::CRC32.checksum(chunk2)
    #   Digest::CRC32.uncombine(combined, crc2, chunk2.bytesize) == Digest::CRC32.checksum(chunk1)
    #
    # @param [Integer] combined_crc
    #   The CRC checksum of the concatenation of the two chunks.
    #
    # @param [Integer] crc2
    #   The CRC checksum of the second chunk of data.
    #
    # @param [Integer] len2
    #   The length in bytes of the second chunk of data.
    #
    # @return [Integer]
    #   The CRC checksum of the first chunk of data.
    #
    # @raise [NotImplementedError]
    #   If WIDTH, TABLE, or REFLECT_INPUT constants are not set properly.
    #
    # @raise [ArgumentError]
    #   If the given length is not a non-negative Integer, or if the CRC
    #   transition matrix is not invertible and the first checksum cannot be
    #   uniquely recovered.
    #
    # @since 0.8.0
    #
    def self.uncombine(combined_crc, crc2, len2)
      width, init_crc, xor_mask = combine_parameters()
      crc_mask = (1 << width) - 1

      matrix = gf2_matrix_power(zero_byte_transition_matrix, combine_length(len2))
      matrix = gf2_matrix_invert(matrix)

      state = gf2_matrix_vector_mul(matrix, (combined_crc & crc_mask) ^ (crc2 & crc_mask))

      (state ^ init_crc ^ xor_mask) & crc_mask
    end

    #
    # Recovers the CRC checksum of the second of two consecutive chunks of
    # data, given the CRC checksum of the concatenation and of the first
    # chunk.
    #
    # @example
    #   combined = Digest::CRC32.checksum(chunk1 + chunk2)
    #   crc1     = Digest::CRC32.checksum(chunk1)
    #   Digest::CRC32.uncombine_last(combined, crc1, chunk2.bytesize) == Digest::CRC32.checksum(chunk2)
    #
    # @param [Integer] combined_crc
    #   The CRC checksum of the concatenation of the two chunks.
    #
    # @param [Integer] crc1
    #   The CRC checksum of the first chunk of data.
    #
    # @param [Integer] len2
    #   The length in bytes of the second chunk of data.
    #
    # @return [Integer]
    #   The CRC checksum of the second chunk of data.
    #
    # @raise [NotImplementedError]
    #   If WIDTH, TABLE, or REFLECT_INPUT constants are not set properly.
    #
    # @raise [ArgumentError]
    #   If the given length is not a non-negative Integer.
    #
    # @since 0.8.0
    #
    def self.uncombine_last(combined_crc, crc1, len2)
      width, init_crc, xor_mask = combine_parameters()
      crc_mask = (1 << width) - 1

      matrix = gf2_matrix_power(zero_byte_transition_matrix, combine_length(len2))

      state = (crc1 & crc_mask) ^ init_crc ^ xor_mask

      (combined_crc & crc_mask) ^ gf2_matrix_vector_mul(matrix, state)
    end

    #
    # Validates and returns the CRC parameters used by the combine methods.
    #
    # @return [Array(Integer, Integer, Integer)]
    #   The width, initial value, and XOR mask of the CRC.
    #
    # @raise [NotImplementedError]
    #   If WIDTH, TABLE, or REFLECT_INPUT constants are not set properly.
    #
    # @api private
    #
    def self.combine_parameters
      unless (width = const_get(:WIDTH)) >= 1
        raise(NotImplementedError, "incompleted #{self} as CRC (expected WIDTH to be 1 or more)")
      end

      if const_get(:TABLE).empty?
        raise(NotImplementedError, "incompleted #{self} as CRC (expected TABLE to be not empty)")
      end

      if const_get(:REFLECT_INPUT).nil?
        raise(NotImplementedError, "incompleted #{self} as CRC (expected REFLECT_INPUT to be not nil)")
      end

      [width, const_get(:INIT_CRC), const_get(:XOR_MASK)]
    end

    #
    # Validates a chunk length for the combine methods.
    #
    # @param [Integer] length
    #   The length in bytes.
    #
    # @return [Integer]
    #   The given length.
    #
    # @raise [ArgumentError]
    #   If the length is not a non-negative Integer.
    #
    # @api private
    #
    def self.combine_length(length)
      unless length.is_a?(Integer) && length >= 0
        raise(ArgumentError, "length must be a non-negative Integer")
      end

      length
    end

    #
    # Builds the state transition matrix (as an Array of column Integers)
    # for feeding a single zero byte into the CRC, mirroring the branches of
    # {#update} for the CRC's width and reflection.
    #
    # @return [Array<Integer>]
    #   The columns of the GF(2) transition matrix.
    #
    # @api private
    #
    def self.zero_byte_transition_matrix
      @zero_byte_transition_matrix ||= begin
        width   = const_get(:WIDTH)
        reflect = const_get(:REFLECT_INPUT)
        table   = const_get(:TABLE)
        mask    = (1 << width) - 1

        (0...width).map do |bit|
          crc = 1 << bit

          state = if reflect
                    if width > 8
                      table[crc & 0xff] ^ (crc >> 8)
                    else
                      # Omit (crc >> 8) since bits upper than the lower 8 bits are always 0
                      table[crc & 0xff]
                    end
                  else
                    if width > 8
                      higher_bit_off = width - 8
                      remain_mask    = ~(-1 << higher_bit_off)

                      table[(crc >> higher_bit_off) & 0xff] ^ ((remain_mask & crc) << 8)
                    else
                      padding = 8 - width

                      # Omit (crc << 8) since bits lower than the upper 8 bits are always 0
                      table[(crc << padding) & 0xff]
                    end
                  end

          state & mask
        end
      end
    end

    #
    # Multiplies a GF(2) matrix, given as an Array of column Integers, with
    # a bit-vector.
    #
    # @param [Array<Integer>] columns
    #   The columns of the matrix.
    #
    # @param [Integer] vector
    #   The bit-vector to multiply.
    #
    # @return [Integer]
    #   The resulting bit-vector.
    #
    # @api private
    #
    def self.gf2_matrix_vector_mul(columns, vector)
      result = 0
      index  = 0

      until vector.zero?
        result ^= columns[index] if (vector & 1) == 1

        vector >>= 1
        index   += 1
      end

      result
    end

    #
    # Composes two GF(2) matrices, given as Arrays of column Integers.
    #
    # @param [Array<Integer>] matrix_a
    #   The matrix to apply second.
    #
    # @param [Array<Integer>] matrix_b
    #   The matrix to apply first.
    #
    # @return [Array<Integer>]
    #   The columns of the composed matrix.
    #
    # @api private
    #
    def self.gf2_matrix_mul(matrix_a, matrix_b)
      matrix_b.map { |column| gf2_matrix_vector_mul(matrix_a, column) }
    end

    #
    # Raises a GF(2) matrix, given as an Array of column Integers, to the
    # given exponent by squaring, so that the work grows with the number of
    # bits of the exponent.
    #
    # @param [Array<Integer>] matrix
    #   The columns of the matrix.
    #
    # @param [Integer] exponent
    #   The non-negative exponent.
    #
    # @return [Array<Integer>]
    #   The columns of the exponentiated matrix.
    #
    # @api private
    #
    def self.gf2_matrix_power(matrix, exponent)
      result = (0...matrix.length).map { |bit| 1 << bit }
      base   = matrix

      while exponent > 0
        result = gf2_matrix_mul(base, result) if (exponent & 1) == 1

        base      = gf2_matrix_mul(base, base)
        exponent >>= 1
      end

      result
    end

    #
    # Inverts a GF(2) matrix, given as an Array of column Integers, using
    # Gauss-Jordan elimination.
    #
    # @param [Array<Integer>] columns
    #   The columns of the matrix.
    #
    # @return [Array<Integer>]
    #   The columns of the inverted matrix.
    #
    # @raise [ArgumentError]
    #   If the matrix is not invertible.
    #
    # @api private
    #
    def self.gf2_matrix_invert(columns)
      width = columns.length

      rows = Array.new(width, 0)

      columns.each_with_index do |column, index|
        width.times do |bit|
          rows[bit] |= (1 << index) unless (column & (1 << bit)).zero?
        end
      end

      inverse = (0...width).map { |bit| 1 << bit }

      width.times do |column|
        pivot = (column...width).find { |row| rows[row][column] == 1 }

        if pivot.nil?
          raise(ArgumentError, "cannot uncombine CRC checksums for #{self}: the CRC transition matrix is not invertible")
        end

        if pivot != column
          rows[column], rows[pivot]       = rows[pivot], rows[column]
          inverse[column], inverse[pivot] = inverse[pivot], inverse[column]
        end

        width.times do |row|
          next if row == column

          if rows[row][column] == 1
            rows[row]    ^= rows[column]
            inverse[row] ^= inverse[column]
          end
        end
      end

      (0...width).map do |index|
        column = 0

        width.times do |bit|
          column |= (1 << bit) unless (inverse[bit] & (1 << index)).zero?
        end

        column
      end
    end

    private_class_method :combine_parameters, :combine_length,
                         :zero_byte_transition_matrix,
                         :gf2_matrix_vector_mul, :gf2_matrix_mul,
                         :gf2_matrix_power, :gf2_matrix_invert

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
