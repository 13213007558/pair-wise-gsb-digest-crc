require 'spec_helper'
require 'digest/crc32'
require 'digest/crc5'

describe Digest::CRC do
  describe '.calibrate' do
    it 'recovers a unique reflected parameter set without enumerating initial values' do
      messages = ['', 'abc', '123456789', "\x00abc", 'different-length']
      samples = messages.map { |message| [message, Digest::CRC32.checksum(message)] }

      solutions = described_class.calibrate(
        width: 32,
        polynomial: 0x04c11db7,
        samples: samples
      )

      expect(solutions.length).to be(1)
      solution = solutions.first

      expect(solution).to be_unique
      expect(solution.reflect_input).to be(true)
      expect(solution.init_crc).to be(0xffffffff)
      expect(solution.xor_mask).to be(0xffffffff)

      crc_class = solution.crc_class
      samples.each do |message, checksum|
        expect(crc_class.checksum(message)).to be(checksum)
      end
    end

    it 'recovers a unique non-reflected parameter set' do
      table = described_class.send(:crc_table, 32, 0x04c11db7, false)
      crc_class = ::Class.new(described_class) do
        const_set(:WIDTH, 32)
        const_set(:REFLECT_INPUT, false)
        const_set(:INIT_CRC, 0x11223344)
        const_set(:XOR_MASK, 0x55667788)
        const_set(:TABLE, table)
      end
      messages = ['', 'abc', '123456789', "\x00x"]
      samples = messages.map { |message| [message, crc_class.checksum(message)] }

      solutions = described_class.calibrate(
        width: 32,
        polynomial: 0x04c11db7,
        samples: samples,
        reflect_input: false
      )

      expect(solutions.length).to be(1)
      solution = solutions.first

      expect(solution).to be_unique
      expect(solution.init_crc).to be(0x11223344)
      expect(solution.xor_mask).to be(0x55667788)

      samples.each do |message, checksum|
        expect(solution.crc_class.checksum(message)).to be(checksum)
      end
    end

    it 'returns a particular solution and a free-variable basis for underdetermined samples' do
      table = described_class.send(:crc_table, 8, 0x07, false)
      crc_class = ::Class.new(described_class) do
        const_set(:WIDTH, 8)
        const_set(:REFLECT_INPUT, false)
        const_set(:INIT_CRC, 0x12)
        const_set(:XOR_MASK, 0x34)
        const_set(:TABLE, table)
      end
      samples = [['abc', crc_class.checksum('abc')]]

      solutions = described_class.calibrate(
        width: 8,
        polynomial: 0x07,
        samples: samples,
        reflect_input: false
      )

      expect(solutions.length).to be(1)
      solution = solutions.first

      expect(solution).not_to be_unique
      expect(solution.free_variables.length).to be(8)

      vectors = solution.free_variables
      expect(vectors).to all(be > 0)
      expect(vectors.uniq.length).to be(vectors.length)

      [
        [false] * 8,
        [true] * 8,
        [true, false, true, false, true, false, true, false]
      ].each do |flags|
        candidate = solution.candidate_for(flags)
        samples.each do |message, checksum|
          expect(candidate.checksum(message)).to be(checksum)
        end
      end
    end

    it 'shows that an empty sample reduces the affine ambiguity' do
      table = described_class.send(:crc_table, 8, 0x07, false)
      crc_class = ::Class.new(described_class) do
        const_set(:WIDTH, 8)
        const_set(:REFLECT_INPUT, false)
        const_set(:INIT_CRC, 0x12)
        const_set(:XOR_MASK, 0x34)
        const_set(:TABLE, table)
      end

      samples = [['abc', crc_class.checksum('abc')]]
      with_empty = samples + [['', crc_class.checksum('')]]

      before = described_class.calibrate(width: 8, polynomial: 0x07, samples: samples,
                                          reflect_input: false).first
      after = described_class.calibrate(width: 8, polynomial: 0x07, samples: with_empty,
                                         reflect_input: false).first

      expect(before.free_variables.length).to be(8)
      expect(after.free_variables.length).to be(1)
      expect(after.candidate_for(true).checksum('abc')).to be(crc_class.checksum('abc'))
    end

    it 'accounts for leading zero bytes and message length' do
      first = Digest::CRC32.checksum('abc')
      second = Digest::CRC32.checksum("\x00abc")

      expect(first).not_to be(second)

      solution = described_class.calibrate(
        width: 32,
        polynomial: 0x04c11db7,
        samples: [['abc', first], ["\x00abc", second]],
        reflect_input: true
      ).first

      expect(solution.free_variables.length).to be(0)
      expect(solution.crc_class.checksum("\x00abc")).to be(second)
    end

    it 'returns no solution for contradictory samples' do
      good = Digest::CRC32.checksum('abc')

      solutions = described_class.calibrate(
        width: 32,
        polynomial: 0x04c11db7,
        samples: [['abc', good], ['abc', good ^ 1]],
        reflect_input: true
      )

      expect(solutions).to be_empty
    end

    it 'supports widths smaller than eight bits' do
      samples = [
        ['', Digest::CRC5.checksum('')],
        ['abc', Digest::CRC5.checksum('abc')],
        ["\x00", Digest::CRC5.checksum("\x00")],
        ['long-message', Digest::CRC5.checksum('long-message')]
      ]

      solutions = described_class.calibrate(
        width: 5,
        polynomial: 0x05,
        samples: samples
      )

      expect(solutions.map(&:reflect_input)).to eq([true])
      solution = solutions.first

      expect(solution).to be_unique
      expect(solution.init_crc).to be(0x1f)
      expect(solution.xor_mask).to be(0x1f)
      samples.each do |message, checksum|
        expect(solution.crc_class.checksum(message)).to be(checksum)
      end
    end

    it 'accepts separate messages and checksums' do
      messages = ['abc', '123456789']
      checksums = messages.map { |message| Digest::CRC32.checksum(message) }

      solution = described_class.calibrate(
        width: 32,
        polynomial: 0x04c11db7,
        messages: messages,
        checksums: checksums,
        reflect_input: true
      ).first

      expect(solution.crc_class.checksum('123456789')).to be(checksums.last)
    end

    it 'rejects samples outside the CRC width' do
      expect do
        described_class.calibrate(
          width: 8,
          polynomial: 0x07,
          samples: [['abc', 0x100]]
        )
      end.to raise_error(ArgumentError, /fit within 8 bits/)
    end

    it 'accepts a generator polynomial including its leading one bit' do
      solution = described_class.calibrate(
        width: 32,
        polynomial: 0x104c11db7,
        samples: [['', Digest::CRC32.checksum('')]],
        reflect_input: true
      ).first

      expect(solution.polynomial).to be(0x04c11db7)
      expect(solution.table).to eq(Digest::CRC32::TABLE)
    end
  end
end
