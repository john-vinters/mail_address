# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file COPYING for details.

defmodule MailAddress do
  @moduledoc """
  Functions to handle RFC5321 Mail Addresses.
  """

  alias MailAddress.CharSet

  @typedoc "Error return type - a tuple containing `:error` and a reason string."
  @type error :: {:error, String.t()}
  @typedoc "Success return type - a tuple containing `:ok` and a `MailAddress` struct."
  @type success :: {:ok, %__MODULE__{}}
  @typedoc "The `MailAddress` struct."
  @type t :: %__MODULE__{
          local_part: String.t(),
          domain: String.t(),
          needs_quoting: boolean
        }

  @doc """
  Address struct.

  The struct *SHOULD* *be* *treated* *as* *opaque*
  and not tampered with directly as it may change, and the `needs_quoting`
  field is cached.

  Callers should use the appropriate functions to get/set fields which
  ensures that everything remains in-sync and valid.
  """
  defstruct local_part: "",
            domain: "",
            needs_quoting: false

  defimpl Inspect, for: MailAddress do
    import Inspect.Algebra

    def inspect(%MailAddress{} = addr, opts) do
      str = MailAddress.encode(addr, false)
      insp = color(str, :string, opts)
      concat(["#MailAddress<", insp, ">"])
    end
  end

  defimpl String.Chars, for: MailAddress do
    def to_string(%MailAddress{} = addr) do
      MailAddress.encode(addr, true)
    end
  end

  defmodule Options do
    @moduledoc "Contains struct to hold configuration."

    @typedoc "The `MailAddress.Options` struct."
    @type t :: %__MODULE__{
            allow_localhost: boolean,
            allow_null: boolean,
            allow_null_local_part: boolean,
            downcase_domain: boolean,
            max_address_length: pos_integer,
            max_domain_length: pos_integer,
            max_local_part_length: pos_integer,
            require_brackets: boolean,
            require_domain: boolean
          }

    @doc """
    Holds the configuration options for handling addresses.

      * `:allow_localhost` - if `true`, allows domain part to be "localhost".
        Defaults to `false`.

      * `:allow_null` - if `true` allows address to be null. Defaults to `false`.

      * `:allow_null_local_part` - if `true` allows address to have an empty
        local part.  Defaults to `false`.

      * `:downcase_domain` - if `true` downcases domain automatically. Defaults to
        `false`.

      * `:max_address_length` - the maximum total length in characters.
        Defaults to 256 (from RFC5321).

      * `:max_domain_length` - the maximum domain length in characters.
        Defaults to 255 (from RFC5321).

      * `:max_local_part_length` - the maximum local part length in characters.
        Defaults to 64 (from RFC5321).

      * `:require_brackets` - if `true`, insists that address must be surrounded
        by angle brackets '<' and '>'.  If `false` the brackets are optional
        and any parsing will stop when either the end of string,
        or a space after the last valid domain character is reached.
        Defaults to `false`.

      * `:require_domain` - if `true` then the address must have a domain
        component unless it is a null address. Defaults to `true`.

    """
    defstruct allow_localhost: false,
              allow_null: false,
              allow_null_local_part: false,
              downcase_domain: false,
              max_address_length: 256,
              max_domain_length: 255,
              max_local_part_length: 64,
              require_brackets: false,
              require_domain: true
  end

  # checks a given local part contains only valid characters.
  # returns either `:ok` or `{:error, error_message}`.
  @spec check_local_part(String.t()) :: :ok | error()
  defp check_local_part(local) when is_binary(local) do
    local
    |> :binary.bin_to_list()
    |> Enum.reduce_while(:ok, fn ch, acc ->
      case CharSet.qpair?(ch) do
        true ->
          {:cont, acc}

        false ->
          {:halt, {:error, "invalid character #{CharSet.format(ch)} in address local part"}}
      end
    end)
  end

  @doc """
  Returns the domain part of the address.

  ## Examples

      iex> MailAddress.domain(%MailAddress{})
      ""

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> MailAddress.domain(addr)
      "example.org"
  """
  @spec domain(MailAddress.t()) :: String.t()
  def domain(%MailAddress{domain: d}), do: d

  @doc """
  Checks whether address has a domain part.

  ## Examples

      iex> MailAddress.domain?(%MailAddress{})
      false

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> MailAddress.domain?(addr)
      true
  """
  @spec domain?(MailAddress.t()) :: boolean
  def domain?(%MailAddress{domain: ""}), do: false
  def domain?(%MailAddress{}), do: true

  @doc """
  Compares domain of given address with `domain` (case-insensitively).
  Returns `true` if the domains are the same, or `false` otherwise.

  ## Examples

      iex> {:ok, addr_1} = MailAddress.new("test", "example.org")
      iex> {:ok, addr_2} = MailAddress.new("another", "example.org")
      iex> MailAddress.domains_equal?(addr_1, "example.org")
      true
      iex> MailAddress.domains_equal?(addr_2, "EXAMPLE.ORG")
      true
      iex> MailAddress.domains_equal?(addr_1, "something_else")
      false
      iex> MailAddress.domains_equal?(addr_1, addr_2)
      true
      iex> MailAddress.domains_equal?(addr_1, %MailAddress{})
      false
  """
  @spec domains_equal?(MailAddress.t(), String.t() | MailAddress.t()) :: boolean
  def domains_equal?(%MailAddress{domain: d1}, domain) when is_binary(domain) do
    String.downcase(d1) == String.downcase(domain)
  end

  def domains_equal?(%MailAddress{domain: d1}, %MailAddress{domain: d2}) do
    String.downcase(d1) == String.downcase(d2)
  end

  @doc """
  Returns address safely encoded, optionally (and by default) bracketed.

  ## Examples

      iex> MailAddress.encode(%MailAddress{}, false)
      ""

      iex> MailAddress.encode(%MailAddress{}, true)
      "<>"

      iex> {:ok, addr, ""} = MailAddress.Parser.parse("test@example.org")
      iex> MailAddress.encode(addr, true)
      "<test@example.org>"

      iex> {:ok, addr, ""} = MailAddress.Parser.parse("\\\"@test\\\"@example.org")
      iex> MailAddress.encode(addr, true)
      "<\\"\\\\@test\\\"@example.org>"
  """
  @spec encode(MailAddress.t(), boolean) :: String.t()
  def encode(_, bracket \\ true)

  def encode(%MailAddress{} = addr, true) do
    enc = encode(addr, false)
    <<?<::size(8), enc::binary, ?>::size(8)>>
  end

  def encode(%MailAddress{local_part: "", domain: ""}, false),
    do: <<>>

  def encode(%MailAddress{needs_quoting: false} = addr, false),
    do: <<addr.local_part::binary, ?@::size(8), addr.domain::binary>>

  def encode(%MailAddress{needs_quoting: true} = addr, false) do
    local =
      addr.local_part
      |> :binary.bin_to_list()
      |> Enum.flat_map(fn ch ->
        case CharSet.atext?(ch) do
          true -> [ch]
          false -> [?\\, ch]
        end
      end)
      |> :binary.list_to_bin()

    <<?"::size(8), local::binary, ?"::size(8), ?@::size(8), addr.domain::binary>>
  end

  @doc """
  Checks whether `addr_1` and `addr_2` are the same.
  The local parts are compared case sensitively, whilst the domain parts
  are compare case insensitively.

  ## Examples

      iex> {:ok, addr_1} = MailAddress.new("test", "example.org")
      iex> {:ok, addr_2} = MailAddress.new("test", "ExAmPlE.ORG")
      iex> MailAddress.equal?(addr_1, addr_2)
      true
      iex> {:ok, addr_3} = MailAddress.new("fred", "ExAmPlE.ORG")
      iex> MailAddress.equal?(addr_1, addr_3)
      false
  """
  @spec equal?(MailAddress.t(), MailAddress.t()) :: boolean
  def equal?(%MailAddress{} = addr_1, %MailAddress{} = addr_2) do
    local_parts_equal?(addr_1, addr_2) && domains_equal?(addr_1, addr_2)
  end

  @doc """
  Returns the local part of the address.

  ## Examples

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> MailAddress.local_part(addr)
      "test"
  """
  @spec local_part(MailAddress.t()) :: String.t()
  def local_part(%MailAddress{local_part: l}), do: l

  @doc """
  Checks whether address has local part set.

  ## Examples

      iex> MailAddress.local_part?(%MailAddress{})
      false

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> MailAddress.local_part?(addr)
      true
  """
  @spec local_part?(MailAddress.t()) :: boolean
  def local_part?(%MailAddress{local_part: ""}), do: false
  def local_part?(%MailAddress{}), do: true

  @doc """
  Compares address local parts (case-sensitively).
  The second parameter may be either a string or a `MailAddress` struct.
  Returns `true` if the local parts are the same, or `false` otherwise.

  ## Examples

      iex> {:ok, addr_1} = MailAddress.new("test", "example.org")
      iex> {:ok, addr_2} = MailAddress.new("test", "example.com")
      iex> MailAddress.local_parts_equal?(addr_1, addr_2)
      true
      iex> MailAddress.local_parts_equal?(addr_1, "test")
      true
      iex> MailAddress.local_parts_equal?(addr_2, "TEST")
      false
  """
  @spec local_parts_equal?(MailAddress.t(), MailAddress.t()) :: boolean
  def local_parts_equal?(%MailAddress{local_part: l1}, local_part) when is_binary(local_part),
    do: l1 == local_part

  def local_parts_equal?(%MailAddress{local_part: l1}, %MailAddress{local_part: l2}),
    do: l1 == l2

  @doc """
  Checks whether domain part of address is 'localhost'.

  ## Examples

      iex> {:ok, addr_1} = MailAddress.new("test", "example.org")
      iex> MailAddress.localhost?(addr_1)
      false

      iex> {:ok, addr_2} = MailAddress.new("test", "localhost", %MailAddress.Options{allow_localhost: true})
      iex> MailAddress.localhost?(addr_2)
      true
  """
  @spec localhost?(MailAddress.t()) :: boolean
  def localhost?(%MailAddress{domain: "localhost"}), do: true
  def localhost?(%MailAddress{}), do: false

  @doc """
  Checks whether the local part of the given address needs quoting.

  The `needs_quoting` flag on the address is updated when the address
  is changed, so calling this function is inexpensive.
  """
  @spec needs_quoting?(MailAddress.t()) :: boolean
  def needs_quoting?(%MailAddress{needs_quoting: nq}), do: nq

  @doc """
  Creates a new `MailAddress` setting both local and domain parts at
  the same time using the provided (or default) `options`.

  NOTE: the local part isn't parsed - it is just checked to ensure that
  it only contains valid characters.  This means that the local part
  should be raw rather than quoted form.

  Returns either `{:ok, new_address}` or `{:error, error_reason}`.

  ## Examples

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> addr
      #MailAddress<test@example.org>

      iex> {:ok, addr} = MailAddress.new("@test", "example.org")
      iex> addr
      #MailAddress<\"\\\@test\"@example.org>

      iex> MailAddress.new("test", "example.org!")
      {:error, "invalid domain"}
  """
  @spec new(String.t(), String.t(), Options.t()) :: {:ok, MailAddress.t()} | error()
  def new(local, domain, %MailAddress.Options{} = options \\ %MailAddress.Options{})
      when is_binary(local) and is_binary(domain) do
    with :ok <- check_local_part(local),
         {:ok, parsed_domain, ""} <- MailAddress.Parser.Domain.parse(domain) do
      %MailAddress{local_part: local, domain: parsed_domain}
      |> MailAddress.Parser.check(options)
    else
      {:ok, _, _} ->
        {:error, "invalid domain"}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Checks whether the address in null (no local part and no domain).

  ## Examples

      iex> MailAddress.null?(%MailAddress{})
      true

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> MailAddress.null?(addr)
      false

      iex> {:ok, addr} = MailAddress.new("", "", %MailAddress.Options{allow_null: true})
      iex> MailAddress.null?(addr)
      true
  """
  @spec null?(MailAddress.t()) :: boolean
  def null?(%MailAddress{local_part: "", domain: ""}), do: true
  def null?(%MailAddress{}), do: false

  @doc """
  Sets the domain part of the address using the provided (or default)
  options.

  Returns either `{:ok, new_address}` or `{:error, error_reason}`.

  ## Examples

      iex> {:ok, addr} = MailAddress.set_domain(%MailAddress{}, "test")
      iex> MailAddress.domain(addr)
      "test"

      iex> {:ok, addr} = MailAddress.new("test", "example.com")
      iex> MailAddress.domain(addr)
      "example.com"
      iex> {:ok, addr} = MailAddress.set_domain(addr, "example.org")
      iex> MailAddress.domain(addr)
      "example.org"
  """
  @spec set_domain(MailAddress.t(), String.t(), Options.t()) :: {:ok, MailAddress.t()} | error()
  def set_domain(
        %MailAddress{} = addr,
        domain,
        %MailAddress.Options{} = options \\ %MailAddress.Options{}
      )
      when is_binary(domain) do
    case MailAddress.Parser.Domain.parse(domain) do
      {:ok, parsed_domain, ""} ->
        %{addr | domain: parsed_domain}
        |> MailAddress.Parser.check(options)

      {:ok, _, _} ->
        {:error, "invalid domain"}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Sets the local part of the address using the provided (or default)
  options.

  NOTE: the local part isn't parsed - it is just checked to ensure that
  it only contains valid characters, consequently it should be in raw
  unquoted format.

  Returns either `{:ok, new_address}` or `{:error, error_reason}`.

  ## Examples

      iex> {:ok, addr} = MailAddress.set_local_part(%MailAddress{}, "test", %MailAddress.Options{require_domain: false})
      iex> MailAddress.local_part(addr)
      "test"

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> MailAddress.local_part(addr)
      "test"
      iex> {:ok, addr} = MailAddress.set_local_part(addr, "other")
      iex> MailAddress.local_part(addr)
      "other"
  """
  @spec set_local_part(MailAddress.t(), String.t(), Options.t()) ::
          {:ok, MailAddress.t()} | error()
  def set_local_part(
        %MailAddress{} = addr,
        local,
        %MailAddress.Options{} = options \\ %MailAddress.Options{}
      )
      when is_binary(local) do
    with :ok <- check_local_part(local) do
      %{addr | local_part: local}
      |> MailAddress.Parser.check(options)
    end
  end
end
