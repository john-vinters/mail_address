# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file COPYING for details.

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

  # credo:disable-for-lines:35
  defp parse_dot_str(<<ch::size(8), rest::binary>> = local, {state, acc}) do
    is_atext = CharSet.atext?(ch)

    case state do
      :dot when is_atext ->
        parse_dot_str(rest, {:other_atom, <<acc::binary, ch::size(8)>>})

      :dot when ch == ?. ->
        {:error, "unexpected dot"}

      :dot ->
        {:error, "unexpected character #{CharSet.format(ch)}"}

      :first_atom when is_atext ->
        parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})

      :first_atom ->
        {:ok, acc, local}

      :other_atom when is_atext ->
        parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})

      :other_atom ->
        {:ok, acc, local}

      :rest_atext when is_atext ->
        parse_dot_str(rest, {:rest_atext, <<acc::binary, ch::size(8)>>})

      :rest_atext when ch == ?. ->
        parse_dot_str(rest, {:dot, <<acc::binary, ch::size(8)>>})

      :rest_atext ->
        {:ok, acc, local}
    end
  end

  defp parse_dot_str("", {state, acc}) do
    case state do
      :dot -> {:error, "local part can't end with a dot"}
      _ -> {:ok, acc, ""}
    end
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
