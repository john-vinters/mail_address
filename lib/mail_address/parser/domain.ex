# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file COPYING for details.

defmodule MailAddress.Parser.Domain do
  @moduledoc false

  alias MailAddress.CharSet

  @doc """
  Parses a domain part.
  Returns `{:ok, domain, remainder}` or `{:error, reason}`.
  """
  @spec parse(String.t()) :: {:ok, String.t(), String.t()} | MailAddress.error()
  def parse(""), do: {:ok, "", ""}

  def parse(domain) when is_binary(domain) do
    with {:ok, subdomain, rem} <- parse_subdomain(domain),
         do: parse_domain_repeat(rem, subdomain)
  end

  # parses @domain, dropping the '@'.
  @spec parse_at(String.t()) :: {:ok, String.t(), String.t()} | MailAddress.error()
  def parse_at(<<?@::size(8), domain::binary>>),
    do: parse(domain)

  def parse_at(domain) when is_binary(domain), do: {:ok, "", domain}

  defp parse_domain_repeat(<<?.::size(8), domain::binary>>, acc) do
    with {:ok, subdomain, rem} <- parse_subdomain(domain) do
      parse_domain_repeat(rem, <<acc::binary, ?.::size(8), subdomain::binary>>)
    end
  end

  defp parse_domain_repeat(domain, acc) when is_binary(domain) and is_binary(acc) do
    if byte_size(acc) < 256 do
      {:ok, acc, domain}
    else
      {:error, "domain must be less than 256 characters in length"}
    end
  end

  # Parses a sub-domain, returning `{:ok, sub-domain, remainder}` or `{:error, reason}`.
  defp parse_subdomain(""), do: {:error, "unexpected end of domain part"}

  defp parse_subdomain(<<ld::size(8), _rest::binary>> = domain) do
    if CharSet.alpha?(ld) || CharSet.digit?(ld) do
      with {ldh, rem} <- parse_ldh_str(domain), do: {:ok, ldh, rem}
    else
      {:error, "invalid character in domain #{CharSet.format(ld)}, expected letter or digit"}
    end
  end

  # Parses Letter-Digit-Hyphen string.
  # Returns `{parsed_ldh_string, remainder}`.
  defp parse_ldh_str(str, acc \\ "")
  defp parse_ldh_str("", acc), do: shuffle_hyphen(acc, "")

  defp parse_ldh_str(<<ldh::size(8), ldh_string::binary>>, acc) do
    case CharSet.letter_digit_hyphen?(ldh) do
      true ->
        parse_ldh_str(ldh_string, <<acc::binary, ldh::size(8)>>)

      false ->
        shuffle_hyphen(acc, <<ldh::size(8), ldh_string::binary>>)
    end
  end

  # moves any hyphen from end of acc onto beginning of rem
  defp shuffle_hyphen(acc, rem) when is_binary(acc) and is_binary(rem) do
    if String.ends_with?(acc, "-") do
      new_acc = binary_part(acc, 0, byte_size(acc) - 1)
      new_rem = <<?-::size(8), rem::binary>>
      {new_acc, new_rem}
    else
      {acc, rem}
    end
  end
end
