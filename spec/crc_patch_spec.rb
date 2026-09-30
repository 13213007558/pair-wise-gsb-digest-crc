require 'spec_helper'
require 'digest/crc1'
require 'digest/crc32'

describe Digest::CRC do
  describe '.solve_patch' do
    let(:data) { (0...256).map(&:chr).join.b }

    let(:mask) do
      mask = "\0".b * data.bytesize
      mask.setbyte(0, 0x04)
      mask.setbyte(255, 0x08)
      mask
    end

    let(:desired) do
      patched = data.dup
      patched.setbyte(0, patched.getbyte(0) ^ 0x04)
      patched.setbyte(255, patched.getbyte(255) ^ 0x08)
      Digest::CRC32.checksum(patched)
    end

    it 'finds a proven minimum patch across distant bit positions' do
      result = Digest::CRC32.solve_patch(data, mask, desired, budget: 100)

      expect(result).to be_found
      expect(result).to be_optimal
      expect(result).to be_proven_minimum
      expect(result.flips).to be(2)
      expect(result.minimum_flips).to be(2)
      expect(result.changes.map { |change| [change.offset, change.bit] }).to eq([[0, 2], [255, 3]])
      expect(Digest::CRC32.checksum(result.patched_data)).to eq(desired)
    end

    it 'preserves every bit outside the allowed mask' do
      result = Digest::CRC32.solve_patch(data, mask, desired, budget: 100)

      data.each_byte.with_index do |original_byte, offset|
        masked_difference = (original_byte ^ result.patched_data.getbyte(offset)) & ~mask.getbyte(offset)
        expect(masked_difference).to be_zero
      end

      result.patch_mask.each_byte.with_index do |patch_byte, offset|
        expect(patch_byte & ~mask.getbyte(offset)).to be_zero
      end
    end

    it 'does not mutate the original data or mask' do
      original_data = data.dup
      original_mask = mask.dup

      Digest::CRC32.solve_patch(data, mask, desired, budget: 100)

      expect(data).to eq(original_data)
      expect(mask).to eq(original_mask)
    end

    it 'returns no solution without confusing it with an exhausted budget' do
      target = Digest::CRC32.checksum(data) ^ 1
      result = Digest::CRC32.solve_patch(data, "\0".b * data.bytesize, target, budget: 0)

      expect(result).not_to be_found
      expect(result.status).to be(:no_solution)
      expect(result.solvable).to be(false)
      expect(result.proven_minimum).to be(false)
      expect(result.budget_exhausted).to be(false)
      expect(result.patched_data).to be_nil
      expect(result.patch_mask).to be_nil
      expect(result.flips).to be_nil
    end

    it 'returns a valid best-effort patch when the proof budget is exhausted' do
      result = Digest::CRC32.solve_patch(data, mask, desired, budget: 1)

      expect(result).to be_found
      expect(result.status).to be(:best_effort)
      expect(result).not_to be_optimal
      expect(result.proven_minimum).to be(false)
      expect(result.minimum_flips).to be_nil
      expect(result.budget_exhausted).to be(true)
      expect(result.candidates_checked).to be(1)
      expect(result.flips).to be(2)
      expect(Digest::CRC32.checksum(result.patched_data)).to eq(desired)
      expect(data.each_byte.with_index.all? { |byte, index|
        ((byte ^ result.patched_data.getbyte(index)) & ~mask.getbyte(index)).zero?
      }).to be(true)
    end

    it 'still returns a feasible patch with a zero proof budget' do
      result = Digest::CRC32.solve_patch(data, mask, desired, budget: 0)

      expect(result.status).to be(:best_effort)
      expect(result.solvable).to be(true)
      expect(result.candidates_checked).to be(0)
      expect(result.budget_exhausted).to be(true)
      expect(result.proven_minimum).to be(false)
      expect(Digest::CRC32.checksum(result.patched_data)).to eq(desired)
    end

    it 'returns an optimal zero-flip patch when the target is already current' do
      result = Digest::CRC32.solve_patch(data, mask, Digest::CRC32.checksum(data), budget: 0)

      expect(result.status).to be(:optimal)
      expect(result.patched_data).to eq(data)
      expect(result.patched_data).not_to equal(data)
      expect(result.patch_mask).to eq("\0".b * data.bytesize)
      expect(result.flips).to be(0)
      expect(result.minimum_flips).to be(0)
      expect(result.proven_minimum).to be(true)
    end

    it 'is available through the short patch alias' do
      result = Digest::CRC32.patch(data, mask, desired, budget: 100)

      expect(result.status).to be(:optimal)
      expect(Digest::CRC32.checksum(result.patched_data)).to eq(desired)
    end

    it 'rejects masks of a different byte length' do
      expect { Digest::CRC32.solve_patch(data, "\0", desired) }.to raise_error(
        ArgumentError, /same byte length/
      )
    end

    it 'supports CRC1 within its byte-sum checksum range' do
      one_byte = 'A'.b
      target  = (Digest::CRC1.checksum(one_byte) + 2) % 256
      bitmask = "\x02".b

      result = Digest::CRC1.solve_patch(one_byte, bitmask, target, budget: 1)

      expect(result.status).to be(:optimal)
      expect(result.flips).to be(1)
      expect(result.patched_data).to eq("C".b)
      expect(Digest::CRC1.checksum(result.patched_data)).to eq(target)
    end
  end
end
