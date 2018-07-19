# MailAddress - RFC5321 Mail Address Handling
# (c) Copyright 2018, John Vinters
# Licence: MIT, see file LICENSE for details.

defmodule MailAddress do
  @moduledoc """
  Functions to handle RFC5321 Mail Addresses.

  The library implements functions for handling email addresses as specified
  mostly by RFC5321.  A large chunk of the address syntax is implemented, with
  a few exceptions:

    * Handling of general address literals in domains (IPv4 and IPv6
      address literals are supported).
    * Handling of internationalized addresses (UTF8, punycode etc).

  The address parser is slightly more permissive than RFC5321 allows,
  as it will tolerate backslash quoted characters in the local part of
  addresses outside of quoted strings - this is technically against the
  RFC5321 grammar, but there are examples everywhere of this sort of address.
  Despite this, encoded addresses produced by the library are always quoted
  correctly.

  ## Creating Addresses

  Addresses may be created a number of ways:

    * `%MailAddress{}` - this will create a null address.

    * Calling `new/3` - this will directly assign a local and domain part.

    * Calling `MailAddress.Parser.parse/2` - this will parse a string into
      an address.

  ### Examples

      iex> %MailAddress{}
      #MailAddress<>

      iex> {:ok, addr} = MailAddress.new("test", "example.org")
      iex> addr
      #MailAddress<test@example.org>

      iex> {:ok, addr, ""} = MailAddress.Parser.parse("test@example.org")
      iex> addr
      #MailAddress<test@example.org>

  ## Modifying Addresses

  Addresses can be modified by a number of functions, which return a new
  address with the appropriate update:

    * `set_domain/3` - updates domain.
    * `set_local_part/3` - updates local part of address.

  ## Querying Addresses

  Addresses can be queryied for their components:

    * `address_literal?/1` - checks if the address has an address literal domain set.
    * `address_literal/1` - returns address literal domain (or `nil` if none).
    * `domain?/1` - checks if the address has a domain set.
    * `domain/1` - returns the address domain.
    * `local_part?/1` - checks if the address has a local part set.
    * `local_part/1` - returns the address local part.
    * `needs_quoting?/1` - checks if the address local part needs quoting.
    * `null?/1` - returns true if the address is null (no local or domain parts).

  ## Comparing and Encoding Addresses

    * `domains_equal?/2` - compares address domains.
    * `encode/2` - encodes address as string, taking care of quoting etc.
    * `equal?/2` - compares two addresses.
    * `local_parts_equal?/2` - compares address local parts.

  ## Parsing Addresses

  The module MailAddress.Parser contains parsing code.

    * `MailAddress.Parser.parse/2` - parses a string into an address.
    * `MailAddress.Parser.valid?/2` - determines if address has valid syntax.

  ## Specifying Options

  The `MailAddress.Options` struct is used to store options for configuring
  the library.  Checks are applied after every change/creation operation.

  ## Protocols

  The library implements the `Inspect` and `String.Chars` protocols for
  `MailAddress` structs.

  The `Inspect` protocol is used in the `iex` shell and by `inspect/2` to
  pretty-print the `MailAddress` struct contents.

  The `String.Chars` protocol enables a `MailAddress` struct to be directly
  converted into an encoded string.

  ## Usage with Ecto

  MailAddress provides cast/dump/load callbacks so that it can be used as
  an `Ecto` type:

  ```elixir
  defmodule EctoExample do
    use Ecto.Schema

    schema "emailtest" do
      field :email, MailAddress
    end
  end
  ```

  In migrations any MailAddress field should be defined as a type which
  can hold a large enough (up to 256 chars) string, for example `:text`.

  Addresses converted using from strings using cast/4 will be checked
  for validity before they are accepted into the database.

  Note that casting is done by default with a permissive set of options
  (allowing null addresses etc) - if you wish to be stricter then you
  can change the defaults in your config.exs (see below), or apply some
  further validation yourself.

  ### config.exs configuration when using with Ecto

  The library uses `:mail_address` as the application name, and the
  following boolean keys, which are either `true` to enable, or `false`
  to disable.

    * `:ecto_allow_address_literal` - IP address literal domains.

    * `:ecto_allow_localhost` - allow `localhost` as domain.

    * `:ecto_allow_null` - allow empty (null) addresses.

    * `:ecto_downcase_domain` - force domain name to lower case.

    * `:ecto_require_domain` - require domain part to be present in non-null
      addresses.

  ## Usage with JSON libraries

  MailAddress can be used with JSON libraries, and typically requires
  implementation of the correct protocols to work, for example to
  encode email addresses with `Poison`, the following needs to be
  done:

  ```elixir
  defimpl Poison.Encoder, for: MailAddress do
    def encode(%MailAddress{} = addr, options) do
      Poison.Encoder.BitString.encode(MailAddress.encode(addr, false), options)
    end
  end
  ```

  This will encode any MailAddress structs as encoded strings.
  """

  alias MailAddress.CharSet

  @typedoc "Error return type - a tuple containing `:error` and a reason string."
  @type error :: {:error, String.t()}

  @typedoc "Represents an IPv4 or IPv6 address."
  @type ip_address :: :inet.ip4_address() | :inet.ip6_address()

  @typedoc "Success return type - a tuple containing `:ok` and a `MailAddress` struct."
  @type success :: {:ok, %__MODULE__{}}

  @typedoc "The `MailAddress` struct."
  @type t :: %__MODULE__{
          address_literal: nil | ip_address(),
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
  defstruct address_literal: nil,
            local_part: "",
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
            allow_address_literal: boolean,
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

      * `:allow_address_literal` - if `true`, allows domain part to be an
        address literal.  Defaults to `false`.

      * `:allow_localhost` - if `true`, allows domain part to be "localhost"
        or the equivalent address literal (`[127.0.0.1]` or `[IPv6:::1]`).
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
    defstruct allow_address_literal: false,
              allow_localhost: false,
              allow_null: false,
              allow_null_local_part: false,
              downcase_domain: false,
              max_address_length: 256,
              max_domain_length: 255,
              max_local_part_length: 64,
              require_brackets: false,
              require_domain: true
  end

  @doc """
  Returns the decoded address literal domain (if any), or nil otherwise.

  ## Examples

      iex> MailAddress.address_literal(%MailAddress{})
      nil

      iex> {:ok, addr} = MailAddress.new("test", "[192.168.0.1]", %MailAddress.Options{allow_address_literal: true})
      iex> MailAddress.address_literal(addr)
      {192, 168, 0, 1}
  """
  @spec address_literal(MailAddress.t()) :: String.t()
  def address_literal(%MailAddress{address_literal: a}), do: a

  @doc """
  Checks whether address has an address literal domain part.

  ## Examples

      iex> MailAddress.address_literal?(%MailAddress{})
      false

      iex> {:ok, addr} = MailAddress.new("test", "[192.168.0.1]", %MailAddress.Options{allow_address_literal: true})
      iex> MailAddress.address_literal?(addr)
      true
  """
  @spec address_literal?(MailAddress.t()) :: boolean
  def address_literal?(%MailAddress{address_literal: nil}), do: false
  def address_literal?(%MailAddress{}), do: true

  @doc false
  @spec cast(String.t() | MailAddress.t()) :: {:ok, MailAddress.t()} :: :error
  def cast(<<addr::binary>>) do
    trimmed_addr = String.trim(addr)

    case MailAddress.Parser.parse(trimmed_addr, ecto_parse_options()) do
      {:ok, %MailAddress{} = parsed, ""} ->
        {:ok, parsed}

      _ ->
        :error
    end
  end

  def cast(%MailAddress{} = addr) do
    {:ok, addr}
  end

  def cast(_), do: :error

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
  @spec check(MailAddress.t(), Options.t()) :: {:ok, MailAddress.t()} | error()
  def check(%MailAddress{} = addr, %MailAddress.Options{} = options) do
    with :ok <- check_domain(addr, options),
         :ok <- check_domain_length(addr, options),
         :ok <- check_domain_address_literal(addr, options),
         :ok <- check_local_part_length(addr, options),
         :ok <- check_length(addr, options),
         :ok <- check_null(addr, options),
         {:ok, addr} <- check_needs_quoting(addr),
         {:ok, addr} <- check_downcase(addr, options),
         do: {:ok, addr}
  end

  # checks the domain isn't null (as long as entire address isn't null).
  @spec check_domain(MailAddress.t(), Options.t()) :: :ok | error()
  defp check_domain(%MailAddress{domain: ""} = addr, %Options{require_domain: true}) do
    if byte_size(addr.local_part) == 0, do: :ok, else: {:error, "domain expected"}
  end

  defp check_domain(%MailAddress{} = addr, %Options{allow_localhost: false}) do
    if domains_equal?(addr, "localhost") do
      {:error, "domain can't be localhost"}
    else
      :ok
    end
  end

  defp check_domain(%MailAddress{}, %MailAddress.Options{}), do: :ok

  # checks the domain isn't an address literal (if configured to do so).
  @spec check_domain_address_literal(MailAddress.t(), Options.t()) :: :ok | error()
  defp check_domain_address_literal(%MailAddress{address_literal: nil}, %Options{
         allow_address_literal: false
       }),
       do: :ok

  defp check_domain_address_literal(%MailAddress{}, %Options{allow_address_literal: false}) do
    {:error, "domain can't be an address literal"}
  end

  defp check_domain_address_literal(%MailAddress{}, %Options{}), do: :ok

  # checks domain length is OK.
  @spec check_domain_length(MailAddress.t(), MailAddress.Options.t()) :: :ok | error()
  defp check_domain_length(%MailAddress{domain: dom}, %MailAddress.Options{} = options) do
    max_length = options.max_domain_length

    if byte_size(dom) > max_length do
      {:error, "domain too long (must be <= #{max_length} characters)"}
    else
      :ok
    end
  end

  # downcases the domain part if required.
  @spec check_downcase(MailAddress.t(), Options.t()) :: {:ok, MailAddress.t()} | error()
  defp check_downcase(%MailAddress{domain: dom} = addr, %Options{downcase_domain: true}) do
    {:ok, %{addr | domain: String.downcase(dom)}}
  end

  defp check_downcase(%MailAddress{} = addr, %MailAddress.Options{}), do: {:ok, addr}

  # checks overall length is OK.
  @spec check_length(MailAddress.t(), MailAddress.Options.t()) :: :ok | error()
  defp check_length(%MailAddress{local_part: loc, domain: dom}, %MailAddress.Options{} = options) do
    max_length = options.max_address_length

    if byte_size(loc) + 1 + byte_size(dom) > max_length do
      {:error, "address too long (must be <= #{max_length} characters)"}
    else
      :ok
    end
  end

  # checks a given local part contains only valid characters.
  # returns either `:ok` or `{:error, error_message}`.
  @spec check_local_part(String.t()) :: :ok | error()
  defp check_local_part(<<local::binary>>) do
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

  # checks local part length is OK.
  @spec check_local_part_length(MailAddress.t(), MailAddress.Options.t()) :: :ok | error()
  defp check_local_part_length(
         %MailAddress{domain: dom, local_part: loc},
         %MailAddress.Options{} = options
       ) do
    max_length = options.max_local_part_length
    len = byte_size(loc)

    cond do
      len > max_length ->
        {:error, "local part too long (must be <= #{max_length} characters"}

      len == 0 && !options.allow_null_local_part && byte_size(dom) > 0 ->
        {:error, "local part can't be null"}

      true ->
        :ok
    end
  end

  # checks to see if address needs quoting
  @spec check_needs_quoting(MailAddress.t()) :: {:ok, MailAddress.t()} | error()
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
  @spec check_null(MailAddress.t(), Options.t()) :: :ok | error()
  defp check_null(%MailAddress{local_part: "", domain: ""}, %Options{allow_null: false}) do
    {:error, "address can't be null"}
  end

  defp check_null(%MailAddress{}, %MailAddress.Options{}), do: :ok

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
      iex> {:ok, addr_3} = MailAddress.new("test", "localhost", %MailAddress.Options{allow_localhost: true})
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
      iex> MailAddress.domains_equal?(addr_3, "localhost")
      true
      iex> MailAddress.domains_equal?(addr_3, "[127.0.0.1]")
      true
      iex> MailAddress.domains_equal?(addr_3, "[IPv6:::1]")
      true
  """
  @spec domains_equal?(MailAddress.t(), String.t() | MailAddress.t()) :: boolean
  def domains_equal?(%MailAddress{domain: d1} = addr, <<domain::binary>>) do
    String.downcase(d1) == String.downcase(domain) ||
      (localhost?(addr) && localhost_string?(domain))
  end

  def domains_equal?(%MailAddress{domain: d1} = a1, %MailAddress{domain: d2} = a2) do
    String.downcase(d1) == String.downcase(d2) || (localhost?(a1) && localhost?(a2))
  end

  @doc false
  @spec dump(MailAddress.t()) :: {:ok, String.t()}
  def dump(%MailAddress{} = addr), do: {:ok, MailAddress.encode(addr, false)}
  def dump(_), do: :error

  # parses options for use with ecto - uses fairly sensible defaults, but
  #  most of these can be overridden using config.exs settings.
  defp ecto_parse_options do
    allow_address_literal = Application.get_env(:mail_address, :ecto_allow_address_literal, true)
    allow_localhost = Application.get_env(:mail_address, :ecto_allow_localhost, false)
    allow_null = Application.get_env(:mail_address, :ecto_allow_null, true)
    downcase_domain = Application.get_env(:mail_address, :ecto_downcase_domain, true)
    require_domain = Application.get_env(:mail_address, :ecto_require_domain, true)

    %MailAddress.Options{
      allow_address_literal: allow_address_literal,
      allow_localhost: allow_localhost,
      allow_null: allow_null,
      allow_null_local_part: false,
      downcase_domain: downcase_domain,
      require_brackets: false,
      require_domain: require_domain
    }
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
    do: <<addr.local_part::binary, encode_domain(addr)::binary>>

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

    <<?"::size(8), local::binary, ?"::size(8), encode_domain(addr)::binary>>
  end

  # encodes domain part, including leading '@' if required.
  defp encode_domain(%MailAddress{domain: ""}) do
    ""
  end

  defp encode_domain(%MailAddress{domain: domain}) do
    <<?@::size(8), domain::binary>>
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

  @doc false
  @spec load(String.t()) :: {:ok, MailAddress.t()} | :error
  def load(<<data::binary>>) do
    case MailAddress.Parser.parse(data, ecto_parse_options()) do
      {:ok, %MailAddress{} = parsed, ""} -> {:ok, parsed}
      _ -> :error
    end
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
  def local_parts_equal?(%MailAddress{local_part: l1}, <<local_part::binary>>),
    do: l1 == local_part

  def local_parts_equal?(%MailAddress{local_part: l1}, %MailAddress{local_part: l2}),
    do: l1 == l2

  @doc """
  Checks whether domain part of address is 'localhost', or the domain
  is an address literal and is [127.0.0.1] or [IPv6:::1].

  ## Examples

      iex> {:ok, addr_1} = MailAddress.new("test", "example.org")
      iex> MailAddress.localhost?(addr_1)
      false

      iex> {:ok, addr_2} = MailAddress.new("test", "localhost", %MailAddress.Options{allow_localhost: true})
      iex> MailAddress.localhost?(addr_2)
      true

      iex> {:ok, addr_3} = MailAddress.new("test", "[127.0.0.1]", %MailAddress.Options{allow_address_literal: true, allow_localhost: true})
      iex> MailAddress.localhost?(addr_3)
      true

      iex> {:ok, addr_4} = MailAddress.new("test", "[192.168.0.1]", %MailAddress.Options{allow_address_literal: true, allow_localhost: true})
      iex> MailAddress.localhost?(addr_4)
      false

      iex> {:ok, addr_5} = MailAddress.new("test", "[IPv6:::1]", %MailAddress.Options{allow_address_literal: true, allow_localhost: true})
      iex> MailAddress.localhost?(addr_5)
      true
  """
  @spec localhost?(MailAddress.t()) :: boolean
  def localhost?(%MailAddress{domain: "localhost"}), do: true
  def localhost?(%MailAddress{address_literal: {127, 0, 0, 1}}), do: true
  def localhost?(%MailAddress{address_literal: {0, 0, 0, 0, 0, 0, 0, 1}}), do: true
  def localhost?(%MailAddress{}), do: false

  @doc """
  Checks to see if the given string is "localhost" or equivalent
  ([127.0.0.1] or [IPv6:::1]).

  ## Examples:

      iex> MailAddress.localhost_string?("test")
      false

      iex> MailAddress.localhost_string?("LOCALHOST")
      true

      iex> MailAddress.localhost_string?("[127.0.0.1]")
      true

      iex> MailAddress.localhost_string?("[127.0.0.1")
      false

      iex> MailAddress.localhost_string?("[192.168.0.1]")
      false

      iex> MailAddress.localhost_string?("[IPv6:::1]")
      true
  """
  @spec localhost_string?(String.t()) :: boolean
  def localhost_string?(<<?[::size(8), _rest::binary>> = str) do
    case MailAddress.Parser.Domain.parse(str) do
      {:ok, _, _, {127, 0, 0, 1}} -> true
      {:ok, _, _, {0, 0, 0, 0, 0, 0, 0, 1}} -> true
      _ -> false
    end
  end

  def localhost_string?(str) do
    String.downcase(str) == "localhost"
  end

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
  def new(
        <<local::binary>>,
        <<domain::binary>>,
        %MailAddress.Options{} = options \\ %MailAddress.Options{}
      ) do
    with :ok <- check_local_part(local),
         {:ok, parsed_domain, "", literal} <- MailAddress.Parser.Domain.parse(domain) do
      %MailAddress{address_literal: literal, local_part: local, domain: parsed_domain}
      |> check(options)
    else
      {:ok, _, _, _} ->
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

      iex> {:ok, addr} = MailAddress.set_domain(%MailAddress{}, "test", %MailAddress.Options{allow_null_local_part: true})
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
        <<domain::binary>>,
        %MailAddress.Options{} = options \\ %MailAddress.Options{}
      ) do
    case MailAddress.Parser.Domain.parse(domain) do
      {:ok, parsed_domain, "", literal} ->
        %{addr | address_literal: literal, domain: parsed_domain}
        |> check(options)

      {:ok, _, _, _} ->
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

      iex> MailAddress.set_domain(%MailAddress{}, "test", %MailAddress.Options{allow_null_local_part: false})
      {:error, "local part can't be null"}

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
        <<local::binary>>,
        %MailAddress.Options{} = options \\ %MailAddress.Options{}
      ) do
    with :ok <- check_local_part(local) do
      %{addr | local_part: local}
      |> check(options)
    end
  end

  @doc false
  def type, do: :string
end
