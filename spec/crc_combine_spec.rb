require "spec_helper"
require "digest/crc"

CRC_FILES = %w[
  crc1
  crc5
  crc8
  crc8_1wire
  crc15
  crc16
  crc16_ccitt
  crc16_dnp
  crc16_genibus
  crc16_kermit
  crc16_modbus
  crc16_qt
  crc16_usb
  crc16_x_25
  crc16_xmodem
  crc16_zmodem
  crc24
  crc32
  crc32_bzip2
  crc32c
  crc32_jam
  crc32_mpeg
  crc32_posix
  crc32_xfer
  crc64
  crc64_jones
  crc64_nvme
  crc64_xz
].freeze

CRC_FILES.each do |file|
  require "digest/#{file}"
end

CRC_SPECS = [
  ["crc1", Digest::CRC1],
  ["crc5", Digest::CRC5],
  ["crc8", Digest::CRC8],
  ["crc8_1wire", Digest::CRC8_1Wire],
  ["crc15", Digest::CRC15],
  ["crc16", Digest::CRC16],
  ["crc16_ccitt", Digest::CRC16CCITT],
  ["crc16_dnp", Digest::CRC16DNP],
  ["crc16_genibus", Digest::CRC16Genibus],
  ["crc16_kermit", Digest::CRC16Kermit],
  ["crc16_modbus", Digest::CRC16Modbus],
  ["crc16_qt", Digest::CRC16QT],
  ["crc16_usb", Digest::CRC16USB],
  ["crc16_x_25", Digest::CRC16X25],
  ["crc16_xmodem", Digest::CRC16XModem],
  ["crc16_zmodem", Digest::CRC16ZModem],
  ["crc24", Digest::CRC24],
  ["crc32", Digest::CRC32],
  ["crc32_bzip2", Digest::CRC32BZip2],
  ["crc32c", Digest::CRC32c],
  ["crc32_jam", Digest::CRC32Jam],
  ["crc32_mpeg", Digest::CRC32MPEG],
  ["crc32_posix", Digest::CRC32POSIX],
  ["crc32_xfer", Digest::CRC32XFER],
  ["crc64", Digest::CRC64],
  ["crc64_jones", Digest::CRC64Jones],
  ["crc64_nvme", Digest::CRC64NVMe],
  ["crc64_xz", Digest::CRC64XZ]
].freeze

describe Digest::CRC do
  describe ".combine and .uncombine" do
    it "matches direct checksums for random splits across all built-in algorithms" do
      random = Random.new(0x43524300)
      data = Array.new(127) { random.bytes(1) }.join.b

      CRC_SPECS.each do |_, klass|
        [0, 1, 5, 64, 65, data.bytesize].each do |split|
          first  = data.byteslice(0, split)
          second = data.byteslice(split, data.bytesize - split)

          first_checksum  = klass.checksum(first)
          second_checksum = klass.checksum(second)
          direct_checksum = klass.checksum(data)

          expect(klass.combine(first_checksum, second_checksum, second.bytesize)).to eq(direct_checksum)
          expect(klass.uncombine(direct_checksum, second_checksum, second.bytesize)).to eq(first_checksum)
          recovered_second = klass.uncombine(
            direct_checksum,
            first_checksum,
            second.bytesize,
            missing: :second
          )
          expect(recovered_second).to eq(second_checksum)
        end
      end
    end

    it "supports empty segments and zero lengths" do
      CRC_SPECS.each do |_, klass|
        empty_checksum = klass.checksum("")

        expect(klass.combine(empty_checksum, empty_checksum, 0)).to eq(empty_checksum)
        expect(klass.uncombine(empty_checksum, empty_checksum, 0)).to eq(empty_checksum)
        expect(klass.uncombine(empty_checksum, empty_checksum, 0, missing: :second)).to eq(empty_checksum)
      end
    end

    it "combines CRC1 checksums as byte sums" do
      expect(Digest::CRC1.combine(200, 100, 3)).to eq(44)
      expect(Digest::CRC1.uncombine(44, 100, 3)).to eq(200)
      expect(Digest::CRC1.uncombine(44, 200, 3, missing: :second)).to eq(100)
    end

    it "accepts lengths larger than 32 bits without iterating by byte" do
      length = (1 << 33) + 17
      random = Random.new(0x43524301)

      [Digest::CRC5, Digest::CRC16Genibus, Digest::CRC32, Digest::CRC64XZ].each do |klass|
        checksum1 = random.rand(1 << klass::WIDTH)
        checksum2 = random.rand(1 << klass::WIDTH)
        combined  = klass.combine(checksum1, checksum2, length)

        expect(klass.uncombine(combined, checksum2, length)).to eq(checksum1)
        expect(klass.uncombine(combined, checksum1, length, missing: :second)).to eq(checksum2)

        empty_checksum = klass.checksum("")
        one = klass.combine(empty_checksum, empty_checksum, length)
        doubled = klass.combine(empty_checksum, one, length)

        expect(klass.combine(empty_checksum, empty_checksum, length * 2)).to eq(doubled)
      end
    end

    it "rejects negative lengths" do
      expect { Digest::CRC32.combine(0, 0, -1) }.to raise_error(ArgumentError)
      expect { Digest::CRC32.uncombine(0, 0, -1) }.to raise_error(ArgumentError)
    end

    it "raises a specific error when reversing is not unique" do
      table = Array.new(256) do |byte|
        crc = byte
        8.times do
          crc = if crc.odd?
                  (crc >> 1) ^ 0x02
                else
                  crc >> 1
                end
        end
        crc
      end

      singular = Class.new(Digest::CRC8)
      singular.const_set(:WIDTH, 8)
      singular.const_set(:REFLECT_INPUT, true)
      singular.const_set(:INIT_CRC, 0x00)
      singular.const_set(:XOR_MASK, 0x00)
      singular.const_set(:TABLE, table.freeze)

      expect { singular.uncombine(0, 0, 1) }.to raise_error(Digest::CRC::NonInvertibleError)
      expect(singular.uncombine(singular.checksum(""), 0, 1, missing: :second)).to eq(0)
    end
  end
end
