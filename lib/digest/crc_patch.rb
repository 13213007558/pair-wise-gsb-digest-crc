require 'digest/crc'

module Digest
  class CRC
    PatchResult = Struct.new(
      :status,
      :feasible,
      :optimal,
      :patch,
      :modified_data,
      :target_checksum,
      :actual_checksum,
      :hamming_weight,
      :flipped_bits,
      :candidates_checked,
      :search_budget,
      keyword_init: true
    ) do
      # Returns whether a valid patch was returned.
      def found?
        !patch.nil?
      end

      # Returns whether linear feasibility proved that no patch exists.
      def infeasible?
        status == :infeasible
      end

      # Returns whether the returned patch has minimum Hamming weight.
      def minimum_proven?
        optimal == true
      end
 
      alias_method :minimum?, :minimum_proven?
      alias_method :proven_minimum?, :minimum_proven?

      def budget_exhausted?
        status == :budget_exhausted
      end
    end

    DEFAULT_PATCH_SEARCH_BUDGET = 10_000

    class << self
      # Finds a bit-masked XOR patch for a target CRC checksum.
      def solve_patch(data, mask, target_checksum, search_budget = DEFAULT_PATCH_SEARCH_BUDGET, **options)
        unless options.empty? || options.keys == [:budget] || options.keys == [:search_budget]
          raise(ArgumentError, "unknown keyword: #{options.keys.first.inspect}")
        end

        budget = options.fetch(:search_budget, options.fetch(:budget, search_budget))
        PatchSolver.new(self, data, mask, target_checksum, budget).solve
      end

      alias_method :find_patch, :solve_patch
      alias_method :patch_for, :solve_patch
    end

    class PatchSolver
      def initialize(crc_class, data, mask, target_checksum, search_budget)
        @crc_class = crc_class
        @data = data.b
        @mask = mask.b
        @target_checksum = target_checksum
        @search_budget = search_budget

        validate_arguments
      end

      def solve
        target_delta = build_equation
        reduction = reduce(target_delta)

        unless reduction[:feasible]
          return result(:infeasible, false, false, nil, nil, nil, nil, nil, 0)
        end

        fallback_positions = selected_positions(reduction[:selector])
        checked = 0

        (0..allowed_positions.length).each do |weight|
          found = nil
          if weight.zero?
            found = [] if target_delta.zero?
          else
            found = catch(:stop_search) do
              each_index_combination(allowed_positions.length, weight) do |indices|
                positions = indices.map { |index| allowed_positions[index] }

                if search_budget && checked >= search_budget
                  throw(:stop_search, :budget)
                end

                if checksum(positions) == target_checksum
                  throw(:stop_search, positions)
                end

                checked += 1
              end

              nil
            end
          end

          return build_result(:budget_exhausted, false, fallback_positions, checked) if found == :budget
          return build_result(:optimal, true, found, checked) if found
        end

        build_result(:optimal, true, fallback_positions, checked)
      end

      def each_index_combination(size, choose, start = 0, chosen = [], &block)
        remaining = choose - chosen.length
        return if remaining < 0 || start + remaining > size

        if remaining.zero?
          yield(chosen.dup)
          return
        end

        (start...(size - remaining + 1)).each do |index|
          chosen << index
          each_index_combination(size, choose, index + 1, chosen, &block)
          chosen.pop
        end
      end

      private

      attr_reader :crc_class, :data, :mask, :target_checksum, :search_budget

      def validate_arguments
        unless data.is_a?(String)
          raise(ArgumentError, 'data must be a binary String')
        end

        unless mask.is_a?(String)
          raise(ArgumentError, 'mask must be a binary String')
        end

        unless data.bytesize == mask.bytesize
          raise(ArgumentError, 'mask must have the same byte length as data')
        end

        unless target_checksum.is_a?(Integer) && target_checksum >= 0
          raise(ArgumentError, 'target_checksum must be a non-negative Integer')
        end

        unless search_budget.nil? || (search_budget.is_a?(Integer) && search_budget >= 0)
          raise(ArgumentError, 'search_budget must be a non-negative Integer or nil')
        end

        unless width > 0 && !reflect_input.nil? && !table.empty?
          raise(NotImplementedError, "#{crc_class} does not define a table-driven CRC")
        end

        if target_checksum > crc_mask
          raise(ArgumentError, "target_checksum is larger than a #{width}-bit CRC value")
        end
      end

      def build_equation
        @basis = []

        allowed_positions.each_with_index do |(byte_index, bit_index), position|
          vector = bit_delta(byte_index, bit_index)
          insert_vector(vector, position)
        end

        target_checksum ^ current_checksum
      end

      def insert_vector(vector, position)
        vector, selector = reduce_vector(vector, position => true)
        return if vector.zero?

        pivot = highest_bit(vector)
        @basis[pivot] = {
          value: vector,
          selector: selector
        }
      end

      def reduce(target)
        residual, selector = reduce_vector(target, {})
        { feasible: residual.zero?, selector: selector }
      end

      def reduce_vector(value, selector)
        while !value.zero?
          pivot = highest_bit(value)
          member = @basis[pivot]
          break unless member

          value ^= member[:value]
          xor_selector(selector, member[:selector])
        end

        [value, selector]
      end

      def xor_selector(left, right)
        right.each_key do |position|
          if left.delete(position) == nil
            left[position] = true
          end
        end
      end

      def selected_positions(selector)
        selector.keys.sort.map { |position| allowed_positions[position] }
      end

      def bit_delta(byte_index, bit_index)
        table_index = if reflect_input
                        1 << bit_index
                      elsif width > 8
                        1 << bit_index
                      else
                        1 << (bit_index + 8 - width)
                      end

        vector = table[table_index]

        advance(vector, data.bytesize - byte_index - 1)
      end

      def advance(vector, zero_bytes)
        return vector if zero_bytes.zero?

        power = zero_transform

        while zero_bytes > 0
          vector = apply_linear(power, vector) if zero_bytes & 1 == 1
          power = square_linear(power)
          zero_bytes >>= 1
        end

        vector
      end

      def zero_transform
        @zero_transform ||= Array.new(width) do |bit|
          if reflect_input
            if width > 8
              input_bit = bit < 8 ? (1 << bit) : 0
              ((bit >= 8 ? (1 << (bit - 8)) : 0) ^ table[input_bit]) & crc_mask
            else
              table[1 << bit]
            end
          elsif width >= 8
            input_bit = bit >= width - 8 ? (1 << (bit - (width - 8))) : 0
            low_bit = bit < width - 8 ? (1 << (bit + 8)) : 0
            (low_bit ^ table[input_bit]) & crc_mask
          else
            table[1 << (bit + 8 - width)]
          end
        end
      end

      def apply_linear(matrix, vector)
        result = 0
        bit = 0

        while vector > 0
          result ^= matrix[bit] if vector & 1 == 1
          vector >>= 1
          bit += 1
        end

        result
      end

      def square_linear(matrix)
        matrix.map { |column| apply_linear(matrix, column) }
      end

      def checksum(positions)
        patched = data.dup

        positions.each do |(byte_index, bit_index)|
          patched.setbyte(byte_index, patched.getbyte(byte_index) ^ (1 << bit_index))
        end

        pure_checksum(patched)
      end

      def build_patch(positions)
        patch = String.new("\0" * data.bytesize, encoding: Encoding::ASCII_8BIT)

        positions.each do |(byte_index, bit_index)|
          patch.setbyte(byte_index, patch.getbyte(byte_index) ^ (1 << bit_index))
        end

        patch
      end

      def build_result(status, optimal, positions, checked)
        patch = build_patch(positions)
        modified_data = data.dup.force_encoding(Encoding::ASCII_8BIT)

        positions.each do |(byte_index, bit_index)|
          modified_data.setbyte(byte_index, modified_data.getbyte(byte_index) ^ (1 << bit_index))
        end

        actual_checksum = pure_checksum(modified_data)
        flipped_bits = positions.map { |byte_index, bit_index| [byte_index, bit_index] }

        result(status, true, optimal, patch, modified_data, actual_checksum, positions.length, flipped_bits, checked)
      end

      def result(status, feasible, optimal, patch, modified_data, actual_checksum, weight, flipped_bits, checked)
        PatchResult.new(
          status: status,
          feasible: feasible,
          optimal: optimal,
          patch: patch,
          modified_data: modified_data,
          target_checksum: target_checksum,
          actual_checksum: actual_checksum,
          hamming_weight: weight,
          flipped_bits: flipped_bits,
          candidates_checked: checked,
          search_budget: search_budget
        ).freeze
      end

      def current_checksum
        @current_checksum ||= pure_checksum(data)
      end

      def pure_checksum(bytes)
        crc = init_crc

        if reflect_input
          if width > 8
            bytes.each_byte do |byte|
              crc = table[byte ^ (crc & 0xff)] ^ (crc >> 8)
            end
          else
            bytes.each_byte do |byte|
              crc = table[byte ^ (crc & 0xff)]
            end
          end
        elsif width > 8
          higher_bit_offset = width - 8
          remain_mask = ~(-1 << higher_bit_offset)

          bytes.each_byte do |byte|
            crc = table[byte ^ ((crc >> higher_bit_offset) & 0xff)] ^ ((crc & remain_mask) << 8)
          end
        else
          padding = 8 - width

          bytes.each_byte do |byte|
            crc = table[byte ^ ((crc << padding) & 0xff)]
          end
        end

        (crc ^ xor_mask) & crc_mask
      end

      def allowed_positions
        @allowed_positions ||= begin
          positions = []

          data.each_byte.with_index do |_, byte_index|
            mask_byte = mask.getbyte(byte_index)
            8.times do |bit_index|
              if mask_byte & (1 << bit_index) != 0
                positions << [byte_index, bit_index]
              end
            end
          end

          positions
        end
      end

      def highest_bit(value)
        value.bit_length - 1
      end

      def width
        crc_class.const_get(:WIDTH)
      end

      def reflect_input
        crc_class.const_get(:REFLECT_INPUT)
      end

      def init_crc
        crc_class.const_get(:INIT_CRC)
      end

      def xor_mask
        crc_class.const_get(:XOR_MASK)
      end

      def table
        crc_class.const_get(:TABLE)
      end

      def crc_mask
        @crc_mask ||= width_mask
      end

      def width_mask
        ~(-1 << width)
      end

    end
  end
end
