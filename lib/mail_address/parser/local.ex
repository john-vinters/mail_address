# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file LICENSE for details.

defmodule MailAddress.Parser.Local do
  @moduledoc false

  alias MailAddress.CharSet

  @doc """
  Parses a local part, updating given address.
  Returns `{:ok, local_part, remainder}` or `{:error, reason}`.
  """
  @spec parse(String.t()) :: {:ok, String.t(), String.t()} | MailAddress.error()
  def parse(<<?"::size(8), local::binary>>), do: parse_quoted_str(local)
  def parse(local) when is_binary(local), do: parse_dot_str(local)

  # parses dot-string.
  @spec parse_dot_str(String.t(), {atom, String.t()}) ::
          {:ok, String.t(), String.t()} | MailAddress.error()
  defp parse_dot_str(_, s \\ {:first_atom, ""})

  # credo:disable-for-lines:44
  defp parse_dot_str(<<ch::size(8), rest::binary>> = local, {state, acc}) do
    is_atext? = CharSet.atext?(ch)

    cond do
      state == :dot && is_atext? ->
        parse_dot_str(rest, {:other_atom, <<acc::binary, ch::size(8)>>})

      state == :dot && ch == ?. ->
        {:error, "unexpected dot"}

      (state == :dot || :first_atom || :other_atom || :rest_atext) && ch == ?\\ ->
        case parse_dot_str_quoted(rest) do
          {:ok, ch, rest} -> parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})
          {:error, _} = err -> err
        end

      state == :dot ->
        {:error, "unexpected character #{CharSet.format(ch)}"}

      state == :first_atom && is_atext? ->
        parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})

      state == :first_atom ->
        {:ok, acc, local}

      state == :other_atom && is_atext? ->
        parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})

      state == :other_atom ->
        {:ok, acc, local}

      state == :rest_atext && is_atext? ->
        parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})

      state == :rest_atext && ch == ?. ->
        parse_dot_str(rest, {:dot, <<acc::binary, ch::size(8)>>})

      state == :rest_atext ->
        {:ok, acc, local}
    end
  end

  defp parse_dot_str("", {state, acc}) do
    case state do
      :dot -> {:error, "local part can't end with a dot"}
      _ -> {:ok, acc, ""}
    end
  end

  defp parse_dot_str_quoted(<<ch::size(8), rest::binary>>) do
    case CharSet.qpair?(ch) do
      true -> {:ok, ch, rest}
      false -> {:error, "invalid quoted character #{CharSet.format(ch)}"}
    end
  end

  defp parse_dot_str_quoted("") do
    {:error, "invalid quoted character"}
  end

  @spec parse_quoted_str(String.t(), String.t()) ::
          {:ok, String.t(), String.t()} | MailAddress.error()
  defp parse_quoted_str(local, acc \\ "")
  defp parse_quoted_str("", _), do: {:error, "unexpected end of quoted string"}

  defp parse_quoted_str(<<?\\::size(8), qp::size(8), local::binary>>, acc) do
    case CharSet.qpair?(qp) do
      true -> parse_quoted_str(local, <<acc::binary, qp::size(8)>>)
      false -> {:error, "invalid quoted character #{CharSet.format(qp)}"}
    end
  end

  defp parse_quoted_str(<<qp::size(8), local::binary>>, acc) do
    cond do
      qp == ?" -> {:ok, acc, local}
      CharSet.qtext?(qp) -> parse_quoted_str(local, <<acc::binary, qp::size(8)>>)
      true -> {:error, "invalid character in quoted string #{CharSet.format(qp)}"}
    end
  end
end
