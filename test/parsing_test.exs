defmodule ParsingTest do
  use ExUnit.Case
  alias MailAddress.Parser
  alias MailAddress.Options
  doctest MailAddress.Parser

  test "parses null address" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("", %Options{allow_null: true})
    assert "" = MailAddress.local_part(addr)
    assert "" = MailAddress.domain(addr)
    assert MailAddress.null?(addr)
    assert false == MailAddress.domain?(addr)
    assert false == MailAddress.local_part?(addr)
  end

  test "rejects null address when configured" do
    assert {:error, "address can't be null"} = Parser.parse("", %Options{allow_null: false})
  end

  test "rejects addresses without domain when configured" do
    assert {:error, "domain expected"} = Parser.parse("test", %Options{require_domain: true})
  end

  test "accepts null address without rejecting empty domain when configured" do
    assert {:ok, %MailAddress{} = addr, ""} =
             Parser.parse("", %Options{allow_null: true, require_domain: true})

    assert "" = MailAddress.local_part(addr)
    assert "" = MailAddress.domain(addr)
    assert MailAddress.null?(addr)
  end

  test "parses ordinary address" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("example@example.org")
    assert "example" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
    assert MailAddress.local_part?(addr)
    assert MailAddress.domain?(addr)
    assert !MailAddress.null?(addr)
  end

  test "parses quoted string local part" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("\"a quoted string\"@example.org")
    assert "a quoted string" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "parses quoted string with quoted pairs local part" do
    assert {:ok, %MailAddress{} = addr, ""} =
             Parser.parse("\"\\a\\ \\q\\u\\o\\t\\e\\d\\ \\s\\t\\r\\i\\n\\g\"@example.org")

    assert "a quoted string" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)

    assert {:ok, %MailAddress{} = addr, ""} =
             Parser.parse("\\a\\ \\q\\u\\o\\t\\e\\d\\ \\s\\t\\r\\i\\n\\g@example.org")

    assert "a quoted string" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "rejects quoted string with partial quoted pair" do
    assert {:error, "unexpected end of quoted string"} = Parser.parse("\"\\a\\\"@example.org")
  end

  test "rejects unterminated quoted string" do
    assert {:error, "unexpected end of quoted string"} = Parser.parse("\"\\a@example.org")
  end

  test "correctly handles multiple @ symbols" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("\"@test@\"@example.org")
    assert "@test@" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "parses address containing dot in local part" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("firstname.lastname@example.org")
    assert "firstname.lastname" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "rejects address local part beginning with dot" do
    assert {:error, _} = Parser.parse(".example@example.org")
    assert {:error, _} = Parser.parse(".\\example@example.org")
  end

  test "rejects address local part ending with dot" do
    assert {:error, _} = Parser.parse("example.@example.org")
    assert {:error, _} = Parser.parse("exampl\\e.@example.org")
  end

  test "rejects address local part with consecutive dots" do
    assert {:error, "unexpected dot"} = Parser.parse("example..example@example.org")
  end

  test "accepts quoted address local part with consecutive dots" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("\"example..example\"@example.org")
    assert "example..example" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("example\\..example@example.org")
    assert "example..example" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("example.\\.example@example.org")
    assert "example..example" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "rejects addresses with consecutive dots in domain" do
    assert {:error, _} = Parser.parse("example@example..org")
  end

  test "rejects addresses with domains starting with a dot" do
    assert {:error, _} = Parser.parse("example@.example.org")
  end

  test "rejects addresses with domains ending with a dot" do
    assert {:error, _} = Parser.parse("example@example.org.")
  end

  test "parses address with only digits in local part" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("1234@example.org")
    assert "1234" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "parses address with only underscores in local part" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("____@example.org")
    assert "____" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "parses address with single label domain" do
    assert {:ok, %MailAddress{} = addr, ""} =
             Parser.parse("test@localhost", %Options{allow_localhost: true})

    assert "test" = MailAddress.local_part(addr)
    assert "localhost" = MailAddress.domain(addr)
  end

  test "parses address with dashes in domain" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("test@localhost-example")
    assert "test" = MailAddress.local_part(addr)
    assert "localhost-example" = MailAddress.domain(addr)
  end

  test "rejects address that has a domain that begins with hyphen" do
    assert {:error, _} = Parser.parse("example@-example.org")
  end

  test "rejects address that has a domain that ends with hyphen" do
    assert {:error, _} = Parser.parse("example@example.org-")
  end

  test "rejects address that have invalid domain syntax" do
    assert {:error, _} = Parser.parse("example@example.o_g")
  end

  test "parses address with atext in local part" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("Aa0!#$%&'*+-/=?^_`{|}~@example.org")
    assert "Aa0!#$%&'*+-/=?^_`{|}~" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "parsed address preserves domain case by default" do
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("test@EXAMPLE.ORG")
    assert "test" = MailAddress.local_part(addr)
    assert "EXAMPLE.ORG" = MailAddress.domain(addr)
  end

  test "parsed address has domain downcased when configured" do
    assert {:ok, %MailAddress{} = addr, ""} =
             Parser.parse("test@EXAMPLE.ORG", %Options{downcase_domain: true})

    assert "test" = MailAddress.local_part(addr)
    assert "example.org" = MailAddress.domain(addr)
  end

  test "test valid complex email addresses" do
    addrs = [
      {"email.address.with+tagging@example.com", "email.address.with+tagging", false},
      {"\"very.(),:;<>[]\\\".VERY.\\\"very@\\\\ \\\"very\\\".unusual\"@example.com",
       "very.(),:;<>[]\".VERY.\"very@\\ \"very\".unusual", true},
      {"#!$%&'*+-/=?^_`{}|~@example.com", "#!$%&'*+-/=?^_`{}|~", false},
      {"\"()<>[]:,;@\\\\\\\"!#$%&'-/=?^_`{}| ~.a0\"@example.com",
       "()<>[]:,;@\\\"!#$%&'-/=?^_`{}| ~.a0", true}
    ]

    Enum.each(addrs, fn {test_addr, local, nq} ->
      assert {:ok, %MailAddress{} = addr, ""} = Parser.parse(test_addr)
      assert local == MailAddress.local_part(addr)
      assert "example.com" == MailAddress.domain(addr)
      assert nq == MailAddress.needs_quoting?(addr)
    end)
  end

  test "parses IPv4 domain literals correctly" do
    opts = %Options{allow_address_literal: true}
    assert {:ok, %MailAddress{} = addr, ""} = Parser.parse("test@[192.168.0.1]", opts)
    assert MailAddress.address_literal(addr) == {192, 168, 0, 1}
    assert MailAddress.address_literal?(addr)

    assert {:error, "domain can't be localhost"} = Parser.parse("test@[127.0.0.1]", opts)
    assert {:error, "invalid IPv4 address literal"} = Parser.parse("test@[127]", opts)
    assert {:error, "invalid IPv4 address literal"} = Parser.parse("test@[127.0.0.0.1]", opts)
    assert {:error, "invalid IPv4 address literal"} = Parser.parse("test@[::1]", opts)
  end

  test "parses IPv6 domain literals correctly" do
    opts = %Options{allow_address_literal: true}

    assert {:ok, %MailAddress{} = addr, ""} =
             Parser.parse("test@[IPv6:::FFFF:192.168.42.2]", opts)

    assert MailAddress.address_literal(addr) == {0, 0, 0, 0, 0, 65535, 49320, 10754}
    assert MailAddress.address_literal?(addr)

    assert {:error, "domain can't be localhost"} = Parser.parse("test@[IPv6:::1]", opts)
    assert {:error, "invalid IPv4 address literal"} = Parser.parse("test@[::1]", opts)

    assert {:error, "invalid IPv6 address literal"} =
             Parser.parse("test@[IPv6:127.0.0.0.1]", opts)
  end
end
