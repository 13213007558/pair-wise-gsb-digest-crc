require 'spec_helper'
require 'digest/crc'
require 'digest/crc5'
require 'digest/crc32'

describe Digest::CRC::Calibrator do
  let(:messages) do
    ['', '1', '12', '123', '\01', '\0\01']
  end

  [
    [false,false,0x12,0x34],
    [false,true,0x12,0x34],
    [true,false,0x12,0x34],
    [true,true,0x12,0x34]
  ].each do |reflect_input,reflect_output,init_crc,xor_mask|
    context "with reflect_input=#{reflect_input} and reflect_output=#{reflect_output}" do
      subject do
        Digest::CRC.build(
          width: 8,
          polynomial: 0x1d,
          init_crc: init_crc,
          xor_mask: xor_mask,
          reflect_input: reflect_input,
          reflect_output: reflect_output
        )
      end

      it 'finds the unique parameter set and verifies every candidate' do
        samples = messages.map { |message| [message,subject.checksum(message)] }
        solutions = Digest::CRC.calibrate(8,0x1d,samples)

        expect(solutions.length).to be(1)

        solution = solutions.first
        expect(solution.reflect_input).to be(reflect_input)
        expect(solution.reflect_output).to be(reflect_output)
        expect(solution).to be_unique
        expect(solution.degree_of_freedom).to be(0)
        expect(solution.init_crc).to be(init_crc)
        expect(solution.xor_mask).to be(xor_mask)
        expect(solution.verify(samples)).to be(true)

        candidate = solution.to_crc_class
        samples.each do |message,expected|
          expect(candidate.checksum(message)).to be(expected)
        end
      end
    end
  end

  it 'recovers the built-in CRC32 parameters without enumerating initial values' do
    samples = ['', '1', '12', '\01', 'hello'].map do |message|
      [message,Digest::CRC32.checksum(message)]
    end

    solution = Digest::CRC.calibrate(32,0x04c11db7,samples).first

    expect(solution.reflect_input).to be(true)
    expect(solution.reflect_output).to be(true)
    expect(solution.init_crc).to be(Digest::CRC32::INIT_CRC)
    expect(solution.xor_mask).to be(Digest::CRC32::XOR_MASK)
    expect(solution.to_crc_class::TABLE).to eq(Digest::CRC32::TABLE)
    expect(solution.verify(samples)).to be(true)
  end

  it 'recovers a sub-byte reflected CRC and its table' do
    samples = ['', '1', '12', '\01'].map do |message|
      [message,Digest::CRC5.checksum(message)]
    end

    solution = Digest::CRC.calibrate(5,0x05,samples).first

    expect(solution.init_crc).to be(Digest::CRC5::INIT_CRC)
    expect(solution.xor_mask).to be(Digest::CRC5::XOR_MASK)
    expect(solution.to_crc_class::TABLE).to eq(Digest::CRC5::TABLE)
    expect(solution.verify(samples)).to be(true)
  end

  it 'returns a particular solution and a free-variable basis for insufficient samples' do
    source = Digest::CRC.build(
      width: 16,
      polynomial: 0x1021,
      init_crc: 0x1234,
      xor_mask: 0x5678,
      reflect_input: false
    )
    samples = [['1',source.checksum('1')],['2',source.checksum('2')]]
    solutions = Digest::CRC.calibrate(16,0x1021,samples)

    expect(solutions).not_to be_empty

    solutions.each do |solution|
      expect(solution.unique?).to be(false)
      expect(solution.degree_of_freedom).to be(16)
      expect(solution.verify(samples)).to be(true)

      solution.free_variables.each do |basis|
        expect([basis.init_crc,basis.xor_mask]).not_to eq([0,0])
      end

      zero = solution.to_crc_class
      one = solution.to_crc_class(1)
      basis = solution.free_variables.first

      samples.each do |message,expected|
        expect(zero.checksum(message)).to be(expected)
        expect(one.checksum(message)).to be(expected)
      end

      expect(one::INIT_CRC).to be(
        solution.init_crc ^ basis.init_crc
      )
      expect(one::XOR_MASK).to be(
        solution.xor_mask ^ basis.xor_mask
      )
    end
  end

  it 'reports an unavoidable free-variable direction caused by the polynomial' do
    samples = ['', '1', '12', '123', '\01'].map do |message|
      source = Digest::CRC.build(
        width: 8,
        polynomial: 0x07,
        init_crc: 0x12,
        xor_mask: 0x34,
        reflect_input: false
      )
      [message,source.checksum(message)]
    end

    solution = Digest::CRC.calibrate(8,0x07,samples).first

    expect(solution.unique?).to be(false)
    expect(solution.degree_of_freedom).to be(1)
    expect(solution.free_variables.first.init_crc).to be(0xfd)
    expect(solution.free_variables.first.xor_mask).to be(0xfd)
    expect(solution.verify(samples)).to be(true)
  end

  it 'returns 2w free variables for no samples' do
    solutions = Digest::CRC.calibrate(8,0x07,[])

    expect(solutions.length).to be(4)
    solutions.each do |solution|
      expect(solution.particular[:init_crc]).to be(0)
      expect(solution.particular[:xor_mask]).to be(0)
      expect(solution.degree_of_freedom).to be(16)
      expect(solution.verify([])).to be(true)
    end
  end

  it 'returns no solutions when samples conflict' do
    solutions = Digest::CRC.calibrate(8,0x07,[['1',0],['1',1]])

    expect(solutions).to eq([])
  end

  it 'accepts hashes and reflection filters' do
    source = Digest::CRC.build(
      width: 8,
      polynomial: 0x1d,
      init_crc: 0x12,
      xor_mask: 0x34,
      reflect_input: true,
      reflect_output: false
    )
    samples = [
      { message: '1', checksum: source.checksum('1') },
      { 'message' => '12', 'crc' => source.checksum('12') }
    ]
    pairs = samples.map do |sample|
      [sample[:message] || sample['message'],sample[:checksum] || sample['crc']]
    end

    solutions = Digest::CRC.calibrate(
      8,0x1d,samples,
      reflect_input: true,
      reflect_output: false
    )

    expect(solutions.length).to be(1)
    expect(solutions.first.verify(pairs)).to be(true)
    expect(solutions.first.to_crc_class.checksum('1')).to be(pairs.first.last)
  end

  it 'rejects invalid samples and parameters' do
    expect { Digest::CRC.calibrate(0,0x07,[['',0]]) }.to raise_error(ArgumentError)
    expect { Digest::CRC.calibrate(8,0x07,[[nil,0]]) }.to raise_error(ArgumentError)
    expect { Digest::CRC.calibrate(8,0x07,[['',256]]) }.to raise_error(ArgumentError)
  end
end
