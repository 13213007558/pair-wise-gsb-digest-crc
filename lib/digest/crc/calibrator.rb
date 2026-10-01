require 'digest/crc'

class Digest::CRC
  class Calibrator
    class InconsistentSamples < StandardError; end

    FreeVariable = Struct.new(:name,:init_crc,:xor_mask,keyword_init: true) do
      def to_h
        {
          name:      name,
          init_crc:  init_crc,
          xor_mask:  xor_mask
        }
      end
    end

    class Solution
      attr_reader :width,:polynomial,:init_crc,:xor_mask,
                  :reflect_input,:reflect_output,:table,:free_basis
      alias free_variables free_basis
      alias xor_in init_crc
      alias xor_out xor_mask
      alias refin reflect_input
      alias refout reflect_output

      def initialize(width:,
                     polynomial:,
                     init_crc:,
                     xor_mask:,
                     reflect_input:,
                     reflect_output:,
                     table:,
                     free_basis: [])
        @width          = width
        @polynomial      = polynomial
        @init_crc        = init_crc
        @xor_mask        = xor_mask
        @reflect_input   = reflect_input
        @reflect_output  = reflect_output
        @table           = table
        @free_basis      = free_basis
      end

      def unique?
        @free_basis.empty?
      end

      def degree_of_freedom
        @free_basis.length
      end

      def particular
        parameters
      end

      def parameters(coefficients = nil)
        init_crc, xor_mask = parameter_values(coefficients)

        {
          width:          @width,
          polynomial:      @polynomial,
          init_crc:        init_crc,
          xor_mask:        xor_mask,
          reflect_input:   @reflect_input,
          reflect_output:  @reflect_output,
          table:           @table
        }
      end

      alias to_h parameters

      def variation(*coefficients)
        parameters(expand_coefficients(coefficients))
      end

      def to_crc_class(*coefficients)
        Digest::CRC.build(**parameters(expand_coefficients(coefficients)))
      end

      alias crc_class to_crc_class
      alias solution to_crc_class

      def checksum(message,*coefficients)
        to_crc_class(*coefficients).checksum(message)
      end

      def verify(samples)
        samples.map do |sample|
          if sample.is_a?(Hash)
            message = sample.fetch(:message) { sample.fetch('message') }
            expected = sample.fetch(:checksum) do
              sample.fetch('checksum') do
                sample.fetch(:crc) { sample.fetch('crc') }
              end
            end
          else
            message,expected = sample
          end

          checksum(message) == expected &&
            @free_basis.each_index.all? do |index|
              coefficients = Array.new(@free_basis.length,0)
              coefficients[index] = 1
              checksum(message,coefficients) == expected
            end
        end.all?
      end

      private

      def expand_coefficients(coefficients)
        return [] if coefficients.nil? || coefficients == [nil]

        if coefficients.length == 1 && coefficients.first.is_a?(Integer)
          mask = coefficients.first
          @free_basis.length.times.map { |index| (mask >> index) & 1 }
        else
          Array(coefficients.flatten)
        end
      end

      def parameter_values(coefficients)
        coefficients = expand_coefficients(coefficients)

        unless coefficients.empty? || coefficients.length == @free_basis.length
          raise(ArgumentError,"expected #{@free_basis.length} free-variable coefficients")
        end

        init_crc = @init_crc
        xor_mask = @xor_mask

        coefficients.each_with_index do |coefficient,index|
          next if coefficient.zero?

          basis = @free_basis[index]
          init_crc ^= basis.init_crc
          xor_mask ^= basis.xor_mask
        end

        [init_crc,xor_mask]
      end
    end

    class LinearSystem
      def initialize(variable_count)
        @variable_count = variable_count
        @rows = []
      end

      def consistent?(coefficients,rhs)
        add_row(coefficients,rhs)
        true
      rescue InconsistentSamples
        false
      end

      def particular_solution
        values = 0

        @rows.each do |row|
          values |= row[:rhs] << row[:pivot]
        end

        values
      end

      def nullspace_basis
        pivot_columns = @rows.map { |row| row[:pivot] }
        free_columns = (0...@variable_count).to_a - pivot_columns

        free_columns.map do |free_column|
          vector = 1 << free_column

          @rows.each do |row|
            if row[:coefficients][free_column] == 1
              vector |= 1 << row[:pivot]
            end
          end

          vector
        end
      end

      private

      def add_row(coefficients,rhs)
        coefficients &= (1 << @variable_count) - 1
        rhs &= 1

        @rows.each do |row|
          if coefficients[row[:pivot]] == 1
            coefficients ^= row[:coefficients]
            rhs ^= row[:rhs]
          end
        end

        return if coefficients.zero? && rhs.zero?

        raise(InconsistentSamples) if coefficients.zero?

        pivot = coefficients.bit_length - 1

        @rows.each do |row|
          if row[:coefficients][pivot] == 1
            row[:coefficients] ^= coefficients
            row[:rhs] ^= rhs
          end
        end

        @rows << {
          pivot:        pivot,
          coefficients: coefficients,
          rhs:          rhs
        }
      end
    end

    class Engine
      attr_reader :width,:reflect_input,:table

      def initialize(width,polynomial,reflect_input)
        @width = width
        @reflect_input = reflect_input
        @mask = (1 << width) - 1
        @table = build_table(polynomial)

        if width > 8
          @remain_mask = (1 << (width - 8)) - 1
        else
          @padding = 8 - width
        end
      end

      def raw_checksum(message)
        crc = 0
        message.each_byte { |byte| crc = update(crc,byte) }
        crc
      end

      def state_matrix(message)
        states = @width.times.map { |bit| 1 << bit }
        zero_state = 0

        message.each_byte do |byte|
          next_zero_state = update(zero_state,byte)

          states.map! do |state|
            difference = state ^ (zero_state & @mask)
            update(difference,byte) ^ next_zero_state
          end

          zero_state = next_zero_state
        end

        states
      end

      private

      def build_table(polynomial)
        polynomial = polynomial_for_table(polynomial)

        Array.new(256) do |index|
          crc = initial_table_entry(index)

          8.times do
            if @reflect_input
              feedback_bit = crc & 1
              crc = crc >> 1
            else
              feedback_bit = (crc >> (@width < 8 ? 7 : @width - 1)) & 1
              crc = (crc << 1) & (@width < 8 ? 255 : @mask)
            end

            crc ^= polynomial if feedback_bit == 1
          end

          crc & @mask
        end.freeze
      end

      def polynomial_for_table(polynomial)
        if @reflect_input
          Digest::CRC.reflect_bits(polynomial & @mask,@width)
        else
          @width < 8 ? ((polynomial & @mask) << (8 - @width)) : (polynomial & @mask)
        end
      end

      def initial_table_entry(index)
        if @reflect_input || @width <= 8
          index
        else
          index << (@width - 8)
        end
      end

      def update(state,byte)
        if @reflect_input
          index = byte ^ (state & 255)
          remainder = @width > 8 ? (state >> 8) : 0
          crc = @table[index] ^ remainder
        else
          if @width > 8
            index = byte ^ ((state >> (@width - 8)) & 255)
            crc = @table[index] ^ ((state & @remain_mask) << 8)
          else
            index = byte ^ ((state << @padding) & 255)
            crc = @table[index]
          end
        end

        crc & @mask
      end
    end

    MODES = [
      [false,false],
      [false,true],
      [true,false],
      [true,true]
    ].freeze

    def initialize(width,polynomial,
                   reflect_input: nil,
                   reflect_output: nil,
                   reflect: nil)
      @width = width
      @polynomial = polynomial
      @reflect_input = reflect_input
      @reflect_output = reflect_output
      @reflect = reflect

      validate_configuration
    end

    def calibrate(samples)
      samples = normalize_samples(samples)

      reflection_modes.filter_map do |reflect_input,reflect_output|
        solve(reflect_input,reflect_output,samples)
      end
    end

    alias call calibrate

    private

    def validate_configuration
      unless @width.is_a?(Integer) && @width >= 1 && @width <= 64
        raise(ArgumentError,"width must be an integer between 1 and 64")
      end

      unless @polynomial.is_a?(Integer) && @polynomial >= 0
        raise(ArgumentError,"polynomial must be a non-negative integer")
      end

      maximum_polynomial = ((1 << (@width + 1)) - 1)
      if @polynomial > maximum_polynomial
        raise(ArgumentError,"polynomial is too large for a #{@width}-bit CRC")
      end

      boolean_options = [
        @reflect_input,
        @reflect_output,
        @reflect
      ]

      unless boolean_options.all? { |value| value == true || value == false || value.nil? }
        raise(ArgumentError,"reflection options must be true, false, or nil")
      end
    end

    def reflection_modes
      if !@reflect_input.nil? && !@reflect_output.nil?
        [[@reflect_input,@reflect_output]]
      elsif !@reflect_input.nil?
        [[@reflect_input,false],[@reflect_input,true]]
      elsif !@reflect_output.nil?
        [[false,@reflect_output],[true,@reflect_output]]
      elsif @reflect == true
        [[true,true]]
      elsif @reflect == false
        [[false,false]]
      else
        MODES
      end
    end

    def normalize_samples(samples)
      samples.map do |sample|
        if sample.is_a?(Hash)
          message = sample.fetch(:message) { sample.fetch('message') }
          checksum = sample.fetch(:checksum) do
            sample.fetch('checksum') do
              sample.fetch(:crc) do
                sample.fetch('crc')
              end
            end
          end
        else
          message, checksum = sample
        end

        validate_sample(message,checksum)
        [message,checksum]
      end
    end

    def validate_sample(message,checksum)
      unless message.is_a?(String)
        raise(ArgumentError,"sample message must be a String")
      end

      unless checksum.is_a?(Integer) && checksum >= 0 && checksum <= value_mask
        raise(ArgumentError,"sample checksum must be between 0 and #{value_mask}")
      end
    end

    def solve(reflect_input,reflect_output,samples)
      engine = Engine.new(@width,@polynomial,reflect_input)
      system = LinearSystem.new(@width * 2)
      reflected_output = reflect_input != reflect_output

      samples.each do |message,checksum|
        observed = reflected_output ? reflect_value(checksum) : checksum
        constant = engine.raw_checksum(message)
        state_columns = engine.state_matrix(message)
        rhs = observed ^ constant

        @width.times do |output_bit|
          coefficients = 1 << (@width + output_bit)

          @width.times do |input_bit|
            if state_columns[input_bit][output_bit] == 1
              coefficients |= 1 << input_bit
            end
          end

          return unless system.consistent?(coefficients,(rhs >> output_bit) & 1)
        end
      end

      build_solution(engine,system,reflect_input,reflect_output,reflected_output)
    end

    def build_solution(engine,system,reflect_input,reflect_output,reflected_output)
      vector = system.particular_solution
      init_crc = vector & value_mask
      xor_mask = vector >> @width
      xor_mask = reflect_value(xor_mask) if reflected_output

      free_basis = system.nullspace_basis.each_with_index.map do |basis,index|
        basis_init = basis & value_mask
        basis_xor = basis >> @width
        basis_xor = reflect_value(basis_xor) if reflected_output

        FreeVariable.new(
          name:      "free_variable_#{index}",
          init_crc:  basis_init,
          xor_mask:  basis_xor
        )
      end

      Solution.new(
        width:          @width,
        polynomial:      @polynomial & value_mask,
        init_crc:        init_crc,
        xor_mask:        xor_mask,
        reflect_input:   reflect_input,
        reflect_output:  reflect_output,
        table:           engine.table,
        free_basis:      free_basis
      )
    end

    def reflect_value(value)
      Digest::CRC.reflect_bits(value,@width)
    end

    def value_mask
      @value_mask ||= (1 << @width) - 1
    end
  end

    def self.calibrate(*arguments,
                       width: nil,
                       polynomial: nil,
                       samples: nil,
                       **remaining_options)
      options = remaining_options

      if arguments.length == 3
        width,polynomial,samples = arguments
      elsif arguments.empty?
      else
        raise(ArgumentError,'expected width, polynomial, and samples')
      end

    Calibrator.new(width,polynomial,**options).calibrate(samples)
  end

  def self.build(*arguments,**attributes)
    if arguments.length == 1
      argument = arguments.first
      attributes = argument.to_h if argument.respond_to?(:to_h)
    elsif !arguments.empty?
      raise(ArgumentError,'expected CRC attributes')
    end

    width = attributes.fetch(:width)
    polynomial = attributes.fetch(:polynomial)
    init_crc = attributes.fetch(:init_crc,0)
    xor_mask = attributes.fetch(:xor_mask,0)
    reflect_input = attributes.fetch(:reflect_input,false)
    reflect_output = attributes.fetch(:reflect_output,nil)
    table = attributes.fetch(:table,nil)
    mask = (1 << width) - 1
    reflect_output = reflect_input if reflect_output.nil?

    Class.new(self) do |crc_class|
      crc_class.const_set(:WIDTH,width)
      crc_class.const_set(:POLYNOMIAL,polynomial & mask)
      crc_class.const_set(:INIT_CRC,init_crc & mask)
      crc_class.const_set(:XOR_MASK,xor_mask & mask)
      crc_class.const_set(:REFLECT_INPUT,reflect_input)
      crc_class.const_set(:REFLECT_OUTPUT,reflect_output)
      crc_class.const_set(:TABLE,table || Calibrator::Engine.new(
        width,polynomial,reflect_input
      ).table)
    end
  end
end
