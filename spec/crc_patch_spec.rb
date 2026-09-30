require 'spec_helper'
require 'digest/crc_patch'
require 'digest/crc32'
require 'digest/crc16_ccitt'

describe Digest::CRC do
  describe '.solve_patch' do
    let(:data) { "hello\x00\x00world".b }

    it 'finds the minimum patch across distant patch regions' do
      mask = ("\x01" + "\x00" * (data.bytesize - 2) + "\x80").b
      modified = data.dup
      modified.setbyte(0, modified.getbyte(0) ^ 0x01)
      modified.setbyte(data.bytesize - 1, modified.getbyte(data.bytesize - 1) ^ 0x80)

      result = Digest::CRC32.solve_patch(data, mask, Digest::CRC32.checksum(modified))

      expect(result.status).to eq(:optimal)
      expect(result).to be_minimum_proven
      expect(result.hamming_weight).to eq(2)
      expect(result.flipped_bits).to eq([[0, 0], [data.bytesize - 1, 7]])
      expect(result.patch).to eq(mask)
      expect(result.modified_data).to eq(modified)
      expect(result.actual_checksum).to eq(result.target_checksum)
      expect(data).to eq("hello\x00\x00world".b)
    end

    it 'preserves every non-maskable bit in the returned patch' do
      mask = ("\x00" * 5 + "\x0f\x0f" + "\x00" * 5).b
      target = Digest::CRC32.checksum("hello\x05\x0aworld".b)

      result = Digest::CRC32.solve_patch(data, mask, target)

      expect(result).to be_found
      result.patch.each_byte.with_index do |byte, index|
        expect(byte & ~mask.getbyte(index)).to eq(0)
      end
      expect(result.actual_checksum).to eq(target)
      expect(Digest::CRC32.checksum(result.modified_data)).to eq(target)
    end

    it 'reports infeasibility without claiming that a search proved it' do
      mask = ("\x01" + "\x00" * (data.bytesize - 1)).b
      target = Digest::CRC32.checksum(data) ^ 1

      result = Digest::CRC32.solve_patch(data, mask, target)

      expect(result.status).to eq(:infeasible)
      expect(result).to be_infeasible
      expect(result.feasible).to eq(false)
      expect(result).not_to be_found
      expect(result.patch).to be_nil
      expect(result.modified_data).to be_nil
      expect(result.hamming_weight).to be_nil
      expect(result.flipped_bits).to be_nil
    end

    it 'returns a proven zero-bit patch when the CRC already matches' do
      target = Digest::CRC32.checksum(data)

      result = Digest::CRC32.solve_patch(data, "\x00" * data.bytesize, target, 0)

      expect(result.status).to eq(:optimal)
      expect(result).to be_minimum_proven
      expect(result.hamming_weight).to eq(0)
      expect(result.patch).to eq("\x00" * data.bytesize)
      expect(result.modified_data).to eq(data)
      expect(result.candidates_checked).to eq(0)
    end

    it 'returns a valid fallback and does not report no solution when the budget runs out' do
      mask = "\xff" * data.bytesize
      target = (Digest::CRC32.checksum(data) + 12345) & 0xffffffff

      result = Digest::CRC32.solve_patch(data, mask, target, 0)

      expect(result.status).to eq(:budget_exhausted)
      expect(result.feasible).to eq(true)
      expect(result).not_to be_minimum_proven
      expect(result).to be_budget_exhausted
      expect(result).to be_found
      expect(result.actual_checksum).to eq(target)
      expect(Digest::CRC32.checksum(result.modified_data)).to eq(target)
      expect(result.candidates_checked).to eq(0)
    end

    it 'stops the search at the configured budget and records checked candidates' do
      mask = "\xff" * 6
      target = (Digest::CRC32.checksum("123456".b) + 999) & 0xffffffff

      result = Digest::CRC32.solve_patch('123456'.b, mask, target, 10)

      expect(result.status).to eq(:budget_exhausted)
      expect(result.candidates_checked).to eq(10)
      expect(result.search_budget).to eq(10)
      expect(result.actual_checksum).to eq(target)
    end

    it 'accepts the search budget as a keyword argument' do
      result = Digest::CRC32.solve_patch(
        '123456'.b,
        "\xff" * 6,
        (Digest::CRC32.checksum('123456'.b) + 999) & 0xffffffff,
        search_budget: 3
      )

      expect(result.status).to eq(:budget_exhausted)
      expect(result.candidates_checked).to eq(3)
      expect(result).to be_found
    end

    it 'supplies the same interface through the patch_for alias' do
      target = Digest::CRC32.checksum(data)

      expect(Digest::CRC32.patch_for(data, "\x00" * data.bytesize, target)).to be_minimum_proven
    end

    it 'works with non-reflected CRC algorithms' do
      data_bytes = "patch-crc".b
      mask = "\x80\x00\x00\x00\x00\x00\x00\x00\x01".b
      modified = data_bytes.dup
      modified.setbyte(0, modified.getbyte(0) ^ 0x80)
      modified.setbyte(8, modified.getbyte(8) ^ 0x01)

      result = Digest::CRC16CCITT.solve_patch(data_bytes, mask, Digest::CRC16CCITT.checksum(modified))

      expect(result.status).to eq(:optimal)
      expect(result).to be_minimum_proven
      expect(result.hamming_weight).to eq(2)
      expect(result.actual_checksum).to eq(Digest::CRC16CCITT.checksum(modified))
    end

    it 'does not mutate the input data' do
      original = data.dup
      mask = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".b
      target = Digest::CRC32.checksum("iello\x00\x00world".b)

      Digest::CRC32.solve_patch(data, mask, target)

      expect(data).to eq(original)
      expect(data.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'rejects masks with a different length' do
      expect { Digest::CRC32.solve_patch(data, "\x00".b, 0) }
        .to raise_error(ArgumentError, 'mask must have the same byte length as data')
    end
  end
end
