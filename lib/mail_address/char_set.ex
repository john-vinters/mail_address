# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file LICENSE for details.

defmodule MailAddress.CharSet do
  @moduledoc false

  @compile {:inline, [alpha?: 1, atext?: 1, digit?: 1, qpair?: 1, special?: 1]}

  @doc "Returns true if passed character value is an alpha."
  @spec alpha?(non_neg_integer) :: boolean
  def alpha?(v) when v in ?A..?Z, do: true
  def alpha?(v) when v in ?a..?z, do: true
  def alpha?(v) when is_integer(v), do: false

  @doc "Returns true if passed character value is an atext."
  @spec atext?(non_neg_integer) :: boolean
  def atext?(v)
      when v in [?!, ?#, ?$, ?%, ?&, ?', ?*, ?+, ?-, ?/, ?=, ??, ?^, ?_, ?`, ?{, ?|, ?}, ?~],
      do: true

  def atext?(v) when is_integer(v), do: alpha?(v) || digit?(v)

  @doc "Returns true if passed character value is a digit."
  @spec digit?(non_neg_integer) :: boolean
  def digit?(v) when v in ?0..?9, do: true
  def digit?(v) when is_integer(v), do: false

  @doc "Formats character so it can safely be used in error messages."
  @spec format(non_neg_integer) :: String.t()
  def format(ch) do
    if qpair?(ch) do
      <<?(::size(8), ch::size(8), ?)::size(8)>>
    else
      "(0x#{Integer.to_string(ch, 16)})"
    end
  end

  @doc "Returns true if passed character is alpha/digit/hyphen."
  @spec letter_digit_hyphen?(non_neg_integer) :: boolean
  def letter_digit_hyphen?(v), do: alpha?(v) || digit?(v) || v == ?-

  @doc "Returns true if passed character is qpair."
  @spec qpair?(non_neg_integer) :: boolean
  def qpair?(v) when v >= 32 and v <= 126, do: true
  def qpair?(_), do: false

  @doc "Returns true if passed character is qtext."
  @spec qtext?(non_neg_integer) :: boolean
  def qtext?(v), do: qpair?(v) && v != 34 && v != 92

  @doc "Returns true if passed character is a special."
  @spec special?(non_neg_integer) :: boolean
  def special?(v) when v in [?(, ?), ?<, ?>, ?[, ?], ?:, ?;, ?@, ?\\, ?,, ?., ?"], do: true
  def special?(v) when is_integer(v), do: false
end
