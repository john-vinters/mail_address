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
  Applies checks and optional domain downcasing to given address using
  passed options.

  This function is automatically called as required by other functions
  in the package, so doesn't normally need to be called unless you
  are messing with the `MailAddress` struct directly (which isn't
  a good idea).

  If successful, returns `{:ok, new_address}`, otherwise returns
  `{:error, error_message}`.
  """
  @spec check(MailAddress.t(), Options.t()) :: {:ok, MailAddress.t()} | MailAddress.error()
  def check(%MailAddress{} = addr, %MailAddress.Options{} = options) do
    with :ok <- check_domain(addr, options),
         :ok <- check_domain_length(addr, options),
         :ok <- check_local_part_length(addr, options),
         :ok <- check_length(addr, options),
         :ok <- check_null(addr, options),
         {:ok, addr} <- check_needs_quoting(addr),
         {:ok, addr} <- check_downcase(addr, options),
         do: {:ok, addr}
  end

  # checks the domain isn't null (as long as entire address isn't null).
  @spec check_domain(MailAddress.t(), Options.t()) :: :ok | MailAddress.error()
  defp check_domain(%MailAddress{domain: ""} = addr, %Options{require_domain: true}) do
    if byte_size(addr.local_part) == 0, do: :ok, else: {:error, "domain expected"}
  end

  defp check_domain(%MailAddress{} = addr, %Options{allow_localhost: false}) do
    if MailAddress.domains_equal?(addr, "localhost") do
      {:error, "domain can't be localhost"}
    else
      :ok
    end
  end

  defp check_domain(%MailAddress{}, %MailAddress.Options{}), do: :ok

  # checks domain length is OK.
  @spec check_domain_length(MailAddress.t(), MailAddress.Options.t()) ::
          {:ok, MailAddress.t()} | MailAddress.error()
  defp check_domain_length(%MailAddress{domain: dom}, %MailAddress.Options{} = options) do
    max_length = options.max_domain_length

    if byte_size(dom) > max_length do
      {:error, "domain too long (must be <= #{max_length} characters)"}
    else
      :ok
    end
  end

  # downcases the domain part if required.
  @spec check_downcase(MailAddress.t(), Options.t()) ::
          {:ok, MailAddress.t()} | MailAddress.error()
  defp check_downcase(%MailAddress{domain: dom} = addr, %Options{downcase_domain: true}) do
    {:ok, %{addr | domain: String.downcase(dom)}}
  end

  defp check_downcase(%MailAddress{} = addr, %MailAddress.Options{}), do: {:ok, addr}

  # checks overall length is OK.
  @spec check_length(MailAddress.t(), MailAddress.Options.t()) ::
          {:ok, MailAddress.t()} | MailAddress.error()
  defp check_length(%MailAddress{local_part: loc, domain: dom}, %MailAddress.Options{} = options) do
    max_length = options.max_address_length

    if byte_size(loc) + 1 + byte_size(dom) > 256 do
      {:error, "address too long (must be <= #{max_length} characters)"}
    else
      :ok
    end
  end

  # checks local part length is OK.
  @spec check_local_part_length(MailAddress.t(), MailAddress.Options.t()) ::
          {:ok, MailAddress.t()} | MailAddress.error()
  defp check_local_part_length(%MailAddress{local_part: loc}, %MailAddress.Options{} = options) do
    max_length = options.max_local_part_length

    if byte_size(loc) > max_length do
      {:error, "local part too long (must be <= #{max_length} characters)"}
    else
      :ok
    end
  end

  # checks to see if address needs quoting
  @spec check_needs_quoting(MailAddress.t()) :: {:ok, MailAddress.t()} | MailAddress.error()
  defp check_needs_quoting(%MailAddress{local_part: "", domain: ""} = addr),
    do: {:ok, %{addr | needs_quoting: false}}

  defp check_needs_quoting(%MailAddress{local_part: ""} = addr),
    do: {:ok, %{addr | needs_quoting: true}}

  defp check_needs_quoting(%MailAddress{local_part: <<?.::size(8), _rest::binary>>} = addr),
    do: {:ok, %{addr | needs_quoting: true}}

  defp check_needs_quoting(%MailAddress{local_part: local} = addr) do
    {needs_quoting, last_dot} =
      local
      |> :binary.bin_to_list()
      |> Enum.reduce({false, false}, fn ch, {nq, ld} = acc ->
        is_dot = ch == ?.

        cond do
          nq -> acc
          is_dot && ld -> {true, ld}
          is_dot -> {nq, true}
          !CharSet.atext?(ch) -> {true, ld}
          true -> {nq, false}
        end
      end)

    {:ok, %{addr | needs_quoting: needs_quoting || last_dot}}
  end

  # checks the address isn't null.
  @spec check_null(MailAddress.t(), Options.t()) :: :ok | MailAddress.error()
  defp check_null(%MailAddress{local_part: "", domain: ""}, %Options{allow_null: false}) do
    {:error, "address can't be null"}
  end

  defp check_null(%MailAddress{}, %MailAddress.Options{}), do: :ok

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
         {:ok, %MailAddress{} = addr2} <- check(addr, options),
         do: {:ok, addr2, rnb}
  end

  # does the main work of parsing without caring about surrounding brackets.
  # this doesn't run checks on the resulting address either.
  @spec parse_apply(String.t()) :: {:ok, MailAddress.t(), String.t()} | MailAddress.error()
  defp parse_apply(raw_addr) when is_binary(raw_addr) do
    with {:ok, local, remaining} <- MailAddress.Parser.Local.parse(raw_addr),
         {:ok, domain, remaining} <- MailAddress.Parser.Domain.parse_at(remaining),
         do: {:ok, %MailAddress{local_part: local, domain: domain}, remaining}
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
    case MailAddress.Parser.parse(address, options) do
      {:ok, %MailAddress{}, ""} -> true
      _ -> false
    end
  end
end
