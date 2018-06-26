# MailAddress

[![Hex.pm](https://img.shields.io/hexpm/v/mail_address.svg)](https://hex.pm/packages/mail_address)

## Introduction

MailAddress is an MIT-licensed package for handling RFC5321 email addresses.

It contains the following features:

  * `MailAddress` contains the struct definition along with utility functions to encode, query or update the struct.

  * `MailAddress.Parser` is a (slightly) configurable parser, which understands most of the RFC5321 address format (currently missing are general address literals, IPv4 and IPv6 literals are now supported).

Note that this package doesn't deal with UTF8, punycode etc, and
attempting to feed UTF8 characters outside the 32..126 range to the
various functions will result in errors.

## Installation

To use the package, add `:mail_address` as a dependency to your `mix.exs`
file:

```elixir
defp deps do
  [
    {:mail_address, "~> 0.5.0"}
  ]
end
```

After running `mix deps.get` the library should be fetched and available
for use.
