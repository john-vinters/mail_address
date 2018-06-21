# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file COPYING for details.

defmodule MailAddress.Parser do
  @moduledoc """
  Functions to parse mail addresses.
  """

  alias MailAddress.CharSet
  alias MailAddress.Options

  @doc """
  Parses an email address, with options configured by the `options`
  parameter.

  Parsing begins at the first character of the string and continues
  until either the closing bracket (if configured to use `require_brackets`
  in the options, or an opening bracket was the first character of the string),
  a character is encountered which would not be valid in a domain, or
  end of string is reached.

  Returns either `{:ok, parsed_address, remainder_of_string}` or
  `{:error, error_reason_string}`.

  ## Examples

      iex> {:ok, addr, ""} = MailAddress.Parser.parse("test@example.org")
      iex> addr
      #MailAddress<test@example.org>

      iex> MailAddress.Parser.parse("test@example.invalid_domain!")
      {:error, "unexpected character (_)"}

      iex> {:ok, addr, ""} = MailAddress.Parser.parse("<>", %MailAddress.Options{require_brackets: true, allow_null: true})
      iex> addr
      #MailAddress<>

      iex> MailAddress.Parser.parse("<>", %MailAddress.Options{require_brackets: true, allow_null: false})
      {:error, "address can't be null"}

      iex> MailAddress.Parser.parse("abc@def", %MailAddress.Options{require_brackets: true})
      {:error, "opening bracket ('<') expected"}

      iex> {:ok, addr, ""} = MailAddress.Parser.parse("test@EXAMPLE.ORG", %MailAddress.Options{downcase_domain: true})
      iex> addr
      #MailAddress<test@example.org>

      iex> {:ok, addr, " some more text"} = MailAddress.Parser.parse("<test@example.org> some more text")
      iex> addr
      #MailAddress<test@example.org>
  """
  @spec parse(String.t(), Options.t()) :: {:ok, MailAddress.t(), String.t()} | MailAddress.error()
  def parse(raw_addr, %MailAddress.Options{} = options \\ %MailAddress.Options{})
      when is_binary(raw_addr) do
    with {:ok, brak, ranb} <- proc_opening_bracket(raw_addr, options),
         {:ok, %MailAddress{} = addr, rem} <- parse_apply(ranb),
         {:ok, rnb} <- proc_closing_bracket(rem, brak),
         {:ok, %MailAddress{} = addr2} <- MailAddress.check(addr, options),
         do: {:ok, addr2, rnb}
  end

  # does the main work of parsing without caring about surrounding brackets.
  # this doesn't run checks on the resulting address either.
  @spec parse_apply(String.t()) :: {:ok, MailAddress.t(), String.t()} | MailAddress.error()
  defp parse_apply(raw_addr) when is_binary(raw_addr) do
    with {:ok, local, remaining} <- MailAddress.Parser.Local.parse(raw_addr),
         {:ok, domain, remaining, literal} <- MailAddress.Parser.Domain.parse_at(remaining),
         do:
           {:ok, %MailAddress{address_literal: literal, local_part: local, domain: domain},
            remaining}
  end

  # checks the closing bracket is present if required.
  defp proc_closing_bracket("", 32), do: {:ok, ""}
  defp proc_closing_bracket(<<32::size(8), rest::binary>>, 32), do: {:ok, rest}

  defp proc_closing_bracket(ch, 32),
    do: {:error, "unexpected character #{CharSet.format(:binary.at(ch, 0))}"}

  defp proc_closing_bracket(<<bk::size(8), rest::binary>>, brak) do
    if bk == brak,
      do: {:ok, rest},
      else: {:error, "closing bracket ('>') expected, got #{CharSet.format(bk)}"}
  end

  defp proc_closing_bracket(_, _), do: {:error, "closing bracket ('>') expected"}

  # checks the opening bracket is present if required.
  @spec proc_opening_bracket(String.t(), Options.t()) ::
          {:ok, non_neg_integer, String.t()} | MailAddress.error()
  defp proc_opening_bracket(<<brak::size(8), rest::binary>> = addr, %Options{
         require_brackets: req_brackets
       }) do
    case brak do
      ?< -> {:ok, ?>, rest}
      _ -> if req_brackets, do: {:error, "opening bracket ('<') expected"}, else: {:ok, 32, addr}
    end
  end

  defp proc_opening_bracket(_, %MailAddress.Options{}), do: {:ok, 32, ""}

  @doc """
  Checks if the given email address string has valid syntax by attempting
  to parse it, using the provided (or default) options.

  Returns `true` if valid, `false` if invalid.

  ## Examples

      iex> MailAddress.Parser.valid?("test@example.org")
      true

      iex> MailAddress.Parser.valid?("@invalid@example.org")
      false

      iex> MailAddress.Parser.valid?("\\\"@invalid\\\"@example.org")
      true
  """
  def valid?(address, %MailAddress.Options{} = options \\ %MailAddress.Options{}) do
    case parse(address, options) do
      {:ok, %MailAddress{}, ""} -> true
      _ -> false
    end
  end
end
