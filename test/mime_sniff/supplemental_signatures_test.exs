defmodule MimeSniff.SupplementalSignaturesTest do
  use ExUnit.Case
  alias MimeSniff.Sniffing

  describe "supplemental audio signatures" do
    test "identifies FLAC" do
      assert Sniffing.from_binary("fLaC" <> <<0x00, 0x00, 0x00, 0x22>>) == {:ok, "audio/flac"}
    end

    test "identifies AMR" do
      assert Sniffing.from_binary("#!AMR\n") == {:ok, "audio/amr"}
    end

    test "identifies AC-3" do
      assert Sniffing.from_binary(<<0x0B, 0x77, 0x12, 0x34>>) == {:ok, "audio/vnd.dolby.dd-raw"}
    end

    test "identifies DTS" do
      assert Sniffing.from_binary(<<0x7F, 0xFE, 0x80, 0x01, 0x00>>) == {:ok, "audio/vnd.dts"}
    end

    test "identifies ASF (WMA/WMV)" do
      asf_guid =
        <<0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C>>

      assert Sniffing.from_binary(asf_guid <> <<0x00>>) == {:ok, "video/x-ms-asf"}
    end

    test "identifies AIFF-C" do
      assert Sniffing.from_binary("FORM" <> <<0x00, 0x00, 0x08, 0x24>> <> "AIFCCOMM") == {:ok, "audio/aiff"}
    end

    test "identifies raw MPEG audio frames and ADTS AAC" do
      assert Sniffing.from_binary(<<0xFF, 0xFB, 0x90, 0x00>>) == {:ok, "audio/mpeg"}
      assert Sniffing.from_binary(<<0xFF, 0xF3, 0x18, 0xC4>>) == {:ok, "audio/mpeg"}
      assert Sniffing.from_binary(<<0xFF, 0xF1, 0x50, 0x80>>) == {:ok, "audio/mpeg"}
    end

    test "does not identify JPEG as MPEG audio" do
      assert Sniffing.from_binary(<<0xFF, 0xD8, 0xFF, 0xE0>> <> <<0x00, 0x10>> <> "JFIF") == {:ok, "image/jpeg"}
    end
  end

  describe "supplemental QuickTime signatures" do
    test "mp4-branded ftyp boxes still resolve to video/mp4 first" do
      assert Sniffing.from_binary(<<0x00, 0x00, 0x00, 0x0C>> <> "ftypmp42") == {:ok, "video/mp4"}

      assert Sniffing.from_binary(<<0x00, 0x00, 0x00, 0x18>> <> "ftypM4A " <> <<0x00, 0x00, 0x02, 0x00>> <> "mp42isom") ==
               {:ok, "video/mp4"}
    end

    test "non-mp4 ftyp brands fall through to video/quicktime" do
      assert Sniffing.from_binary(<<0x00, 0x00, 0x00, 0x14>> <> "ftypqt  " <> <<0x00, 0x00, 0x02, 0x00>>) ==
               {:ok, "video/quicktime"}
    end

    test "identifies other QuickTime top-level atoms" do
      for atom <- ~w(moov mdat free skip wide pnot) do
        assert Sniffing.from_binary(<<0x00, 0x00, 0x00, 0x08>> <> atom) == {:ok, "video/quicktime"},
               "expected #{atom} to identify as video/quicktime"
      end
    end
  end

  describe "byte-based sniff window" do
    test "sniff_len trims by bytes, not by UTF-8 graphemes" do
      utf8_heavy = String.duplicate("é", 40)
      assert {:ok, _} = Sniffing.from_binary(utf8_heavy, sniff_len: 16)
    end
  end
end
