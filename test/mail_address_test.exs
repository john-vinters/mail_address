defmodule MailAddressTest do
  use ExUnit.Case
  alias MailAddress.Parser
  alias MailAddress.Options
  doctest MailAddress

  test "comparing addresses is done with correct regard to upper/lower case" do
    assert {:ok, %MailAddress{} = addr1, ""} = Parser.parse("test@EXAMPLE.ORG")
    assert "test" = MailAddress.local_part(addr1)
    assert "EXAMPLE.ORG" = MailAddress.domain(addr1)

    assert {:ok, %MailAddress{} = addr2, ""} =
             Parser.parse("test@EXAMPLE.ORG", %Options{downcase_domain: true})

    assert "test" = MailAddress.local_part(addr2)
    assert "example.org" = MailAddress.domain(addr2)

    assert {:ok, %MailAddress{} = addr3, ""} =
             Parser.parse("TEST@Example.Org", %Options{downcase_domain: false})

    assert "TEST" = MailAddress.local_part(addr3)
    assert "Example.Org" = MailAddress.domain(addr3)
    assert MailAddress.equal?(addr1, addr2)
    assert !MailAddress.equal?(addr1, addr3)
    assert !MailAddress.equal?(addr2, addr3)
    assert MailAddress.local_parts_equal?(addr1, addr2)
    assert !MailAddress.local_parts_equal?(addr1, addr3)
    assert !MailAddress.local_parts_equal?(addr2, addr3)
    assert MailAddress.domains_equal?(addr1, addr2)
    assert MailAddress.domains_equal?(addr1, addr3)
    assert MailAddress.domains_equal?(addr2, addr3)
  end
end
