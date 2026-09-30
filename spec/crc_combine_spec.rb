require 'spec_helper'
require 'digest/crc'
require 'digest/crc1'
require 'digest/crc5'
require 'digest/crc8'
require 'digest/crc8_1wire'
require 'digest/crc15'
require 'digest/crc16'
require 'digest/crc16_ccitt'
require 'digest/crc16_dnp'
require 'digest/crc16_genibus'
require 'digest/crc16_kermit'
require 'digest/crc16_modbus'
require 'digest/crc16_qt'
require 'digest/crc16_usb'
require 'digest/crc16_x_25'
require 'digest/crc16_xmodem'
require 'digest/crc16_zmodem'
require 'digest/crc24'
require 'digest/crc32'
require 'digest/crc32_bzip2'
require 'digest/crc32_jam'
require 'digest/crc32_mpeg'
require 'digest/crc32_posix'
require 'digest/crc32_xfer'
require 'digest/crc32c'
require 'digest/crc64'
require 'digest/crc64_jones'
require 'digest/crc64_nvme'
require 'digest/crc64_xz'

describe Digest::CRC do
  crc_classes = [
    Digest::CRC5,
    Digest::CRC8,
    Digest::CRC8_1Wire,
    Digest::CRC15,
    Digest::CRC16,
    Digest::CRC16CCITT,
    Digest::CRC16DNP,
    Digest::CRC16Genibus,
    Digest::CRC16Kermit,
    Digest::CRC16Modbus,
    Digest::CRC16QT,
    Digest::CRC16USB,
    Digest::CRC16X25,
    Digest::CRC16XModem,
    Digest::CRC16ZModem,
    Digest::CRC24,
    Digest::CRC32,
    Digest::CRC32BZip2,
    Digest::CRC32c,
    Digest::CRC32Jam,
    Digest::CRC32MPEG,
    Digest::CRC32POSIX,
    Digest::CRC32XFER,
    Digest::CRC64,
    Digest::CRC64Jones,
    Digest::CRC64NVMe,
    Digest::CRC64XZ
  ]

  describe ".combine" do
    crc_classes.each do |crc_class|
      context "with #{crc_class}" do
        it "equals the checksum of the concatenated data" do
          random = Random.new(12345)

          10.times do
            data  = random.bytes(random.rand(0..256))
            split = random.rand(0..data.bytesize)
            chunk1 = data[0...split]
            chunk2 = data[split..] || ''

            combined = crc_class.combine(
              crc_class.checksum(chunk1),
              crc_class.checksum(chunk2),
              chunk2.bytesize
            )

            expect(combined).to eq(crc_class.checksum(data))
          end
        end
      end
    end

    it "handles a large chunk split" do
      random = Random.new(12345)
      data   = random.bytes(100_000)
      chunk1 = data[0...60_000]
      chunk2 = data[60_000..]

      combined = Digest::CRC32.combine(
        Digest::CRC32.checksum(chunk1),
        Digest::CRC32.checksum(chunk2),
        chunk2.bytesize
      )

      expect(combined).to eq(Digest::CRC32.checksum(data))
    end

    context "with an empty second chunk" do
      it "returns the first checksum" do
        crc1 = Digest::CRC32.checksum('hello')

        expect(Digest::CRC32.combine(crc1, Digest::CRC32.checksum(''), 0)).to eq(crc1)
      end
    end

    context "with an empty first chunk" do
      it "returns the second checksum" do
        crc2 = Digest::CRC32.checksum('world')

        expect(Digest::CRC32.combine(Digest::CRC32.checksum(''), crc2, 5)).to eq(crc2)
      end
    end

    context "with two empty chunks" do
      it "returns the empty checksum" do
        empty = Digest::CRC32.checksum('')

        expect(Digest::CRC32.combine(empty, empty, 0)).to eq(empty)
      end
    end

    context "with a length greater than 32 bits" do
      let(:crc1) { Digest::CRC32.checksum('hello') }
      let(:crc2) { Digest::CRC32.checksum('world') }
      let(:len2) { (1 << 40) + 12345 }

      it "round-trips through uncombine" do
        combined = Digest::CRC32.combine(crc1, crc2, len2)

        expect(Digest::CRC32.uncombine(combined, crc2, len2)).to eq(crc1)
      end

      it "is associative" do
        crc3 = 0xdeadbeef
        len3 = (1 << 33) + 7

        left  = Digest::CRC32.combine(Digest::CRC32.combine(crc1, crc2, len2), crc3, len3)
        right = Digest::CRC32.combine(crc1, Digest::CRC32.combine(crc2, crc3, len3), len2 + len3)

        expect(left).to eq(right)
      end
    end

    context "with an invalid length" do
      it "raises ArgumentError for a negative length" do
        expect { Digest::CRC32.combine(0, 0, -1) }.to raise_error(ArgumentError)
      end

      it "raises ArgumentError for a non-Integer length" do
        expect { Digest::CRC32.combine(0, 0, 1.5) }.to raise_error(ArgumentError)
        expect { Digest::CRC32.combine(0, 0, '10') }.to raise_error(ArgumentError)
      end
    end

    context "with an incomplete CRC class" do
      it "raises NotImplementedError" do
        expect { Digest::CRC.combine(0, 0, 0) }.to raise_error(NotImplementedError)
      end
    end

    context "with a CRC class without a table" do
      it "raises NotImplementedError" do
        expect { Digest::CRC1.combine(0, 0, 0) }.to raise_error(NotImplementedError)
      end
    end
  end

  describe ".uncombine" do
    crc_classes.each do |crc_class|
      context "with #{crc_class}" do
        it "recovers the first checksum" do
          random = Random.new(12345)

          10.times do
            data  = random.bytes(random.rand(0..256))
            split = random.rand(0..data.bytesize)
            chunk1 = data[0...split]
            chunk2 = data[split..] || ''

            crc1     = crc_class.checksum(chunk1)
            crc2     = crc_class.checksum(chunk2)
            combined = crc_class.checksum(data)

            expect(crc_class.uncombine(combined, crc2, chunk2.bytesize)).to eq(crc1)
          end
        end

        it "recovers the second checksum via uncombine_last" do
          random = Random.new(12345)

          10.times do
            data  = random.bytes(random.rand(0..256))
            split = random.rand(0..data.bytesize)
            chunk1 = data[0...split]
            chunk2 = data[split..] || ''

            crc1     = crc_class.checksum(chunk1)
            crc2     = crc_class.checksum(chunk2)
            combined = crc_class.checksum(data)

            expect(crc_class.uncombine_last(combined, crc1, chunk2.bytesize)).to eq(crc2)
          end
        end
      end
    end

    context "with a zero length" do
      it "recovers the first checksum of an empty second chunk" do
        crc1 = Digest::CRC32.checksum('hello')

        expect(Digest::CRC32.uncombine(crc1, Digest::CRC32.checksum(''), 0)).to eq(crc1)
      end
    end

    context "with an invalid length" do
      it "raises ArgumentError" do
        expect { Digest::CRC32.uncombine(0, 0, -1) }.to raise_error(ArgumentError)
        expect { Digest::CRC32.uncombine_last(0, 0, -1) }.to raise_error(ArgumentError)
      end
    end

    context "with a custom CRC whose polynomial is not invertible" do
      subject(:degenerate_crc) do
        # A reflected polynomial of 0x01 lacks the high bit, so each bit
        # step loses information and the transition matrix is singular.
        table = (0..255).map do |byte|
          crc = byte
          8.times { crc = (crc & 1).zero? ? (crc >> 1) : ((crc >> 1) ^ 0x01) }
          crc
        end

        Class.new(Digest::CRC) do
          const_set(:WIDTH, 8)
          const_set(:REFLECT_INPUT, true)
          const_set(:INIT_CRC, 0x00)
          const_set(:XOR_MASK, 0x00)
          const_set(:TABLE, table.freeze)
        end
      end

      it "still combines" do
        expect(degenerate_crc.combine(0x12, 0x34, 5)).to be_a(Integer)
      end

      it "raises ArgumentError when uncombining" do
        expect { degenerate_crc.uncombine(0x12, 0x34, 5) }.to raise_error(ArgumentError, /not invertible/)
      end
    end

    context "with a custom CRC of non-byte width" do
      subject(:crc12) do
        # CRC-12 polynomial x**12 + x**11 + x**3 + x**2 + x + 1 (0x80f),
        # non-reflected, table generated for a 12-bit register.
        poly = 0x80f
        mask = (1 << 12) - 1

        table = (0..255).map do |byte|
          crc = (byte << 4) & mask
          8.times { crc = ((crc << 1) ^ ((crc & (1 << 11)).zero? ? 0 : poly)) & mask }
          crc
        end

        Class.new(Digest::CRC) do
          const_set(:WIDTH, 12)
          const_set(:REFLECT_INPUT, false)
          const_set(:INIT_CRC, 0x000)
          const_set(:XOR_MASK, 0x000)
          const_set(:TABLE, table.freeze)
        end
      end

      it "combines and uncombines consistently" do
        random = Random.new(12345)

        10.times do
          data  = random.bytes(random.rand(0..256))
          split = random.rand(0..data.bytesize)
          chunk1 = data[0...split]
          chunk2 = data[split..] || ''

          crc1     = crc12.checksum(chunk1)
          crc2     = crc12.checksum(chunk2)
          combined = crc12.checksum(data)

          expect(crc12.combine(crc1, crc2, chunk2.bytesize)).to eq(combined)
          expect(crc12.uncombine(combined, crc2, chunk2.bytesize)).to eq(crc1)
          expect(crc12.uncombine_last(combined, crc1, chunk2.bytesize)).to eq(crc2)
        end
      end
    end
  end
end
