require 'digest'

module Digest
  #
  # Base class for all CRC algorithms.
  #
  class CRC < Digest::Class

    #
    # Represents one bit changed in a CRC patch.
    #
    PatchChange = Struct.new(
      :offset,
      :bit,
      :old_bit,
      :new_bit,
      :old_byte,
      :new_byte,
      keyword_init: true
    )

    #
    # Represents the result of searching for a CRC patch.
    #
    PatchResult = Struct.new(
      :status,
      :solvable,
      :patched_data,
      :patch_mask,
      :changes,
      :flips,
      :minimum_flips,
      :proven_minimum,
      :candidates_checked,
      :budget_exhausted,
      keyword_init: true
    ) do
      def found?
        status != :no_solution
      end

      def solvable?
        solvable
      end

      def optimal?
        status == :optimal
      end

      def best_effort?
        status == :best_effort
      end

      def no_solution?
        status == :no_solution
      end

      def proven_minimum?
        proven_minimum
      end

      def minimum_hamming_weight
        minimum_flips
      end

      alias flip_count flips
      alias bit_flips flips
      alias hamming_weight flips
      alias minimum_proven? proven_minimum?
      alias solved? found?
      alias minimum_bit_flips minimum_hamming_weight
    end

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

    # The default number of candidate patches to check while searching.
    PATCH_SEARCH_BUDGET = 10_000

    #
    # Finds a patch that changes the CRC checksum of `data` to `target_checksum`.
    #
    # Only set bits in `allowed_bitmask` may be changed. Bit 0 is the least
    # significant bit of a byte. Distant set bits are handled independently; no
    # contiguous alignment or four-byte grouping is assumed.
    #
    # @param [String] data
    #   The original binary data. It is not modified.
    #
    # @param [String] allowed_bitmask
    #   A binary mask with the same length as `data`. Every set bit marks a bit
    #   that may be flipped.
    #
    # @param [Integer] target_checksum
    #   The desired CRC checksum.
    #
    # @param [Integer] budget
    #   The maximum number of candidate patches whose CRC is directly
    #   recalculated while proving a minimum solution.
    #
    # @return [PatchResult]
    #   The concrete patch, resulting data, and proof status.
    #
    def self.solve_patch(data, allowed_bitmask, target_checksum, budget: PATCH_SEARCH_BUDGET)
      validate_patch_arguments(data, allowed_bitmask, target_checksum, budget)

      original  = data.b
      mask      = allowed_bitmask.b
      positions = mutable_bit_positions(mask)
      baseline  = checksum(original)

      if baseline == target_checksum
        return patch_result(
          :optimal, original, positions, 0, 0, true, false, target_checksum
        )
      end

      fallback = patch_fallback(positions, original, baseline, target_checksum)

      if fallback.nil?
        return PatchResult.new(
          status: :no_solution,
          solvable: false,
          patched_data: nil,
          patch_mask: nil,
          changes: [],
          flips: nil,
          minimum_flips: nil,
          proven_minimum: false,
          candidates_checked: 0,
          budget_exhausted: false
        )
      end

      remaining_budget = budget == Float::INFINITY ? Float::INFINITY : budget.to_i
      checked          = 0

      (1..positions.size).each do |weight|
        combinations = positions.each_index.to_a.combination(weight)
        checked_here = 0

        combinations.each do |selected_indices|
          break if remaining_budget != Float::INFINITY && checked_here >= remaining_budget

          checked += 1
          checked_here += 1

          patched = original.dup
          selected_indices.each do |index|
            flip_bit!(patched, positions[index])
          end

          if checksum(patched) == target_checksum
            return patch_result(
              :optimal, original, positions,
              selected_indices, checked, true, false, target_checksum
            )
          end
        end

        if remaining_budget != Float::INFINITY
          remaining_budget -= checked_here

          if remaining_budget.zero? && checked_here < combinations.size
            return patch_result(
              :best_effort, original, positions,
              fallback, checked, false, true, target_checksum
            )
          end
        end
      end

      patch_result(
        :best_effort, original, positions,
        fallback, checked, false, false, target_checksum
      )
    end

    class << self
      alias_method :patch, :solve_patch
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

    def self.validate_patch_arguments(data, allowed_bitmask, target_checksum, budget)
      unless data.is_a?(String)
        raise(ArgumentError, "data must be a String")
      end

      unless allowed_bitmask.is_a?(String)
        raise(ArgumentError, "allowed_bitmask must be a String")
      end

      if data.bytesize != allowed_bitmask.bytesize
        raise(ArgumentError, "allowed_bitmask must have the same byte length as data")
      end

      unless self.valid_patch_target?(target_checksum)
        raise(ArgumentError, "target_checksum is outside the CRC width")
      end

      unless budget.is_a?(Integer) || budget == Float::INFINITY
        raise(ArgumentError, "budget must be a non-negative Integer or Float::INFINITY")
      end

      unless budget >= 0
        raise(ArgumentError, "budget must be non-negative")
      end
    end

    def self.valid_patch_target?(target_checksum)
      return false unless target_checksum.is_a?(Integer)

      target_checksum >= 0 && target_checksum <= (~(-1 << const_get(:WIDTH)))
    end

    def self.mutable_bit_positions(mask)
      positions = []

      mask.each_byte.with_index do |byte, offset|
        0.upto(7) do |bit|
          positions << [offset, bit] unless (byte & (1 << bit)).zero?
        end
      end

      positions
    end

    def self.patch_fallback(positions, data, baseline, target_checksum)
      linear_patch_fallback(positions, data, baseline, target_checksum)
    end

    def self.linear_patch_fallback(positions, data, baseline, target_checksum)
      basis         = {}
      basis_sources = {}
      target_delta = target_checksum ^ baseline

      positions.each_with_index do |position, index|
        vector  = singleton_checksum(data, position) ^ baseline
        sources = 1 << index

        basis.each_key.sort.reverse_each do |pivot|
          next if vector.nobits?(1 << pivot)

          vector  ^= basis[pivot]
          sources ^= basis_sources[pivot]
        end

        next if vector.zero?

        pivot = vector.bit_length - 1
        next if basis.key?(pivot)

        basis[pivot] = vector
        basis_sources[pivot] = sources

        break if basis.size == const_get(:WIDTH)
      end

      remaining = target_delta
      selected  = 0

      basis.each_key.sort.reverse_each do |pivot|
        next if remaining.nobits?(1 << pivot)

        remaining ^= basis[pivot]
        selected  ^= basis_sources[pivot]
      end

      return nil unless remaining.zero?

      selected
    end

    def self.singleton_checksum(data, position)
      patched = data.dup
      flip_bit!(patched, position)
      checksum(patched)
    end

    def self.flip_bit!(data, position)
      offset, bit = position
      bit_value   = 1 << bit

      data.setbyte(offset, data.getbyte(offset) ^ bit_value)
      data
    end

    def self.patch_result(status, original, positions, selected_mask, checked, proven, budget_exhausted, expected_checksum)
      selected_indices =
        if selected_mask.is_a?(Integer)
          selected_mask.bit_length.times.select { |index| selected_mask[index] == 1 }
        else
          selected_mask
        end

      selected_positions = selected_indices.map { |index| positions[index] }
      new_bytes = {}
      changes   = []
      patched   = original.dup
      xor_mask  = "\0".b * original.bytesize

      selected_positions.sort.each do |offset, bit|
        bit_value = 1 << bit
        old_byte  = new_bytes.fetch(offset) { original.getbyte(offset) }
        old_bit   = (old_byte >> bit) & 1
        new_byte  = old_byte ^ bit_value
        new_bit   = old_bit ^ 1

        new_bytes[offset] = new_byte
        patched.setbyte(offset, new_byte)
        xor_mask.setbyte(offset, xor_mask.getbyte(offset) ^ bit_value)

        changes << PatchChange.new(
          offset: offset,
          bit: bit,
          old_bit: old_bit,
          new_bit: new_bit,
          old_byte: old_byte,
          new_byte: new_byte
        )
      end

      unless checksum(patched) == expected_checksum
        raise(RuntimeError, "internal patch solver produced an incorrect CRC")
      end

      PatchResult.new(
        status: status,
        solvable: true,
        patched_data: patched,
        patch_mask: xor_mask,
        changes: changes,
        flips: selected_positions.size,
        minimum_flips: proven ? selected_positions.size : nil,
        proven_minimum: proven,
        candidates_checked: checked,
        budget_exhausted: budget_exhausted
      )
    end

    private_class_method(
      :validate_patch_arguments,
      :valid_patch_target?,
      :mutable_bit_positions,
      :patch_fallback,
      :linear_patch_fallback,
      :singleton_checksum,
      :flip_bit!,
      :patch_result
    )

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
