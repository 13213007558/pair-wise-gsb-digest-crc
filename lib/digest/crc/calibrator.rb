require 'digest/crc'

module Digest
  class CRC
    class CalibrationSolution
      Parameters = Struct.new(:init_crc, :xor_mask, :reflect_input, keyword_init: true)

      attr_reader :width, :polynomial, :reflect_input, :free_variables

      def initialize(width, polynomial, table, reflect_input, particular, free_variables)
        @width = width
        @polynomial = polynomial
        @table = table
        @reflect_input = reflect_input
        @particular = particular
        @init_crc = particular & CRC.send(:bit_mask, width)
        @xor_mask = particular >> width
        @free_variables = free_variables
      end

      def init_crc
        @init_crc
      end
      alias initial_crc init_crc
      alias initial_value init_crc
      alias initial init_crc

      def xor_mask
        @xor_mask
      end
      alias final_xor xor_mask
      alias xor_out xor_mask

      def reflected?
        @reflect_input
      end
      alias reflect_input? reflected?

      def unique?
        @free_variables.empty?
      end
      alias determined? unique?

      def parameters
        Parameters.new(
          init_crc: init_crc,
          xor_mask: xor_mask,
          reflect_input: reflect_input
        )
      end
      def to_h
        parameters.to_h
      end

      def [](name)
        parameters.public_send(name)
      end

      def parameters_for(*bits)
        value = @particular

        bits.flatten.each_with_index do |enabled, index|
          value ^= @free_variables[index].to_i if enabled && @free_variables[index]
        end

        Parameters.new(
          init_crc: value & CRC.send(:bit_mask, @width),
          xor_mask: value >> @width,
          reflect_input: @reflect_input
        )
      end

      def free_variable_parameters
        @free_variables.map do |vector|
          Parameters.new(
            init_crc: vector & CRC.send(:bit_mask, @width),
            xor_mask: vector >> @width,
            reflect_input: false
          )
        end
      end

      def candidate_for(*bits)
        candidate = parameters_for(bits.flatten)
        init_crc = candidate.init_crc
        xor_mask = candidate.xor_mask
        table = @table
        width = @width
        reflect_input = @reflect_input

        candidate_polynomial = @polynomial

        ::Class.new(CRC) do
          const_set(:WIDTH, width)
          const_set(:POLYNOMIAL, candidate_polynomial)
          const_set(:REFLECT_INPUT, reflect_input)
          const_set(:INIT_CRC, init_crc)
          const_set(:XOR_MASK, xor_mask)
          const_set(:TABLE, table)
          define_method(:update, CRC.instance_method(:update))
        end
      end

      def crc_class(base_class = CRC)
        table = @table
        width = @width
        polynomial = @polynomial
        init_crc = @init_crc
        xor_mask = @xor_mask
        reflect_input = @reflect_input

        ::Class.new(base_class) do
          const_set(:WIDTH, width)
          const_set(:POLYNOMIAL, polynomial)
          const_set(:REFLECT_INPUT, reflect_input)
          const_set(:INIT_CRC, init_crc)
          const_set(:XOR_MASK, xor_mask)
          const_set(:TABLE, table)
          define_method(:update, CRC.instance_method(:update))
        end
      end
      alias to_crc_class crc_class

      def table
        @table
      end

      def checksum(data)
        crc = @init_crc
        CRC.send(:update_state, crc, data, @table, @width, @reflect_input) ^ @xor_mask
      end

      def ==(other)
        other.is_a?(CalibrationSolution) &&
          width == other.width &&
          polynomial == other.polynomial &&
          reflect_input == other.reflect_input &&
          particular_vector == other.particular_vector &&
          free_variable_vectors == other.free_variable_vectors
      end

      def eql?(other)
        self == other
      end

      def hash
        [width, polynomial, reflect_input, particular_vector, free_variable_vectors].hash
      end

      def inspect
        "#<#{self.class} width=#{width} polynomial=0x#{polynomial.to_s(16)} " \
          "init_crc=0x#{init_crc.to_s(16)} xor_mask=0x#{xor_mask.to_s(16)} " \
          "reflect_input=#{reflect_input} free_variables=#{free_variables.length}>"
      end

      protected

      def particular_vector
        @particular
      end

      def free_variable_vectors
        @free_variables.dup
      end
    end

    def self.calibrate(width: nil, polynomial: nil, poly: nil, samples: nil,
                       messages: nil, checksums: nil, reflect_input: nil, reflected: nil,
                       reflect: nil, reflection: nil)
      polynomial ||= poly
      reflect_input = reflected if reflect_input.nil?
      reflect_input = reflect if reflect_input.nil?
      reflect_input = reflection if reflect_input.nil?
      samples ||= Array(messages).zip(Array(checksums))
      samples = normalize_calibration_samples(samples, width) if width.is_a?(Integer)

      if samples.empty?
        raise(ArgumentError, "samples must not be empty")
      end

      unless width.is_a?(Integer) && width >= 1 && width <= 64
        raise(ArgumentError, "width must be an Integer between 1 and 64")
      end

      samples = normalize_calibration_samples(samples, width)

      unless reflect_input.nil? || reflect_input == true || reflect_input == false
        raise(ArgumentError, "reflect_input must be true, false, or nil")
      end

      mask = bit_mask(width)
      unless polynomial.is_a?(Integer) && polynomial >= 0 && polynomial <= (mask << 1 | 1)
        raise(ArgumentError, "polynomial must fit within #{width + 1} bits")
      end

      polynomial &= mask

      conventions = [true, false].select do |reflected|
        reflect_input.nil? || reflect_input == reflected
      end

      conventions.filter_map do |reflected|
        table = crc_table(width, polynomial, reflected)
        calibrate_convention(width, polynomial, table, reflected, samples)
      end
    end

    def self.normalize_calibration_samples(samples, width)
      samples = samples.to_a if samples.is_a?(Hash)

      samples.map do |sample|
        data, checksum = sample

        unless data.is_a?(String)
          raise(ArgumentError, "sample message must be a String")
        end

        unless checksum.is_a?(Integer) && checksum >= 0
          raise(ArgumentError, "sample checksum must be a non-negative Integer")
        end

        if checksum > bit_mask(width)
          raise(ArgumentError, "sample checksum must fit within #{width} bits")
        end

        [data, checksum]
      end
    end

    private_class_method def self.calibrate_convention(width, polynomial, table, reflected, samples)
      rows = []
      observed = 0
      equation = 0
      transforms = {}

      samples.each do |data, checksum|
        transforms[data] ||= [
          state_transform_rows(data, table, width, reflected),
          update_state(0, data, table, width, reflected)
        ]
        transform_rows, constant = transforms[data]
        target = checksum ^ constant

        width.times do |bit|
          rows << (transform_rows[bit] | (1 << (width + bit)))
          observed |= ((target >> bit) & 1) << equation
          equation += 1
        end
      end

      particular, basis = solve_linear_system(rows, observed, width * 2)
      return nil unless particular

      CalibrationSolution.new(
        width, polynomial, table, reflected, particular, basis
      )
    end

    private_class_method def self.state_transform_rows(data, table, width, reflected)
      basis = Array.new(width) { |bit| 1 << bit }
      update_basis(basis, data, table, width, reflected)

      Array.new(width) do |output_bit|
        mask = 0
        basis.each_with_index do |value, input_bit|
          mask |= 1 << input_bit unless ((value >> output_bit) & 1).zero?
        end
        mask
      end
    end

    private_class_method def self.update_basis(basis, data, table, width, reflected)
      data.each_byte do |byte|
        basis.each_index do |bit|
          basis[bit] = linear_transformed_state(basis[bit], byte, table, width, reflected)
        end
      end
    end

    private_class_method def self.update_state(state, data, table, width, reflected)
      data.each_byte do |byte|
        state = transformed_state(state, byte, table, width, reflected)
      end
      state
    end

    private_class_method def self.transformed_state(state, byte, table, width, reflected)
      if reflected
        index = byte ^ (state & 0xff)
        result = table[index] ^ (state >> 8)
      else
        if width > 8
          shift = width - 8
          index = byte ^ ((state >> shift) & 0xff)
          result = table[index] ^ ((state & bit_mask(shift)) << 8)
        else
          index = byte ^ ((state << (8 - width)) & 0xff)
          result = table[index]
        end
      end

      result & bit_mask(width)
    end

    private_class_method def self.linear_transformed_state(state, byte, table, width, reflected)
      if reflected
        index = state & 0xff
        table[byte ^ index] ^ table[byte] ^ (state >> 8)
      elsif width > 8
        shift = width - 8
        top = (state >> shift) & 0xff
        table[byte ^ top] ^ table[byte] ^ ((state & bit_mask(shift)) << 8)
      else
        top = (state << (8 - width)) & 0xff
        table[byte ^ top] ^ table[byte]
      end & bit_mask(width)
    end

    private_class_method def self.solve_linear_system(rows, observed, variable_count)
      rows = rows.dup
      pivot_rows = Array.new(variable_count)
      row_index = 0

      variable_count.times do |column|
        pivot = (row_index...rows.length).find do |index|
          rows[index].bit_length > column && rows[index][column] == 1
        end

        next unless pivot

        rows[row_index], rows[pivot] = rows[pivot], rows[row_index]
        observed = swap_bits(observed, row_index, pivot)

        rows.each_with_index do |row, index|
          next if index == row_index || row[column].zero?

          rows[index] = row ^ rows[row_index]
          observed = xor_bit(observed, index, observed[row_index])
        end

        pivot_rows[column] = row_index
        row_index += 1
      end

      rows.each_with_index do |row, index|
        return nil if row.zero? && observed[index] == 1
      end

      particular = 0
      pivot_rows.each_with_index do |pivot_row, column|
        next unless pivot_row
        particular |= observed[pivot_row] << column
      end

      basis = (0...variable_count).filter_map do |column|
        next if pivot_rows[column]

        vector = 1 << column
        pivot_rows.each_with_index do |pivot_row, pivot_column|
          next unless pivot_row
          vector |= 1 << pivot_column if rows[pivot_row][column] == 1
        end
        vector
      end

      [particular, basis]
    end

    private_class_method def self.swap_bits(value, first, second)
      first_bit = (value >> first) & 1
      second_bit = (value >> second) & 1
      value ^= (first_bit ^ second_bit) << first
      value ^= (first_bit ^ second_bit) << second
      value
    end

    private_class_method def self.xor_bit(value, index, enabled)
      value ^= enabled << index
      value
    end

    private_class_method def self.crc_table(width, polynomial, reflected)
      polynomial = reverse_bits(polynomial, width) if reflected

      Array.new(256) do |byte|
        if reflected
          crc = byte
          8.times do
            feedback = crc & 1
            crc >>= 1
            crc ^= polynomial if feedback == 1
          end
        elsif width >= 8
          crc = byte << (width - 8)
          8.times do
            feedback = (crc >> (width - 1)) & 1
            crc = (crc << 1) & bit_mask(width)
            crc ^= polynomial if feedback == 1
          end
        else
          crc = byte
          8.times do
            feedback = crc & 0x80
            crc = (crc << 1) & 0xff
            crc ^= polynomial if feedback != 0
          end
        end

        crc & bit_mask(width)
      end.freeze
    end

    private_class_method def self.reverse_bits(value, width)
      width.times.sum do |bit|
        ((value >> bit) & 1) << (width - 1 - bit)
      end
    end

    private_class_method def self.bit_mask(width)
      (1 << width) - 1
    end
  end
end
