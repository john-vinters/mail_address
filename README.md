# MailAddress

## Introduction

MailAddress is an MIT-licensed package for handling RFC5321 email addresses.

It contains the following features:

  * `MailAddress` contains the struct definition along with utility functions to encode, query or update the struct.

  * `MailAddress.Parser` is a (slightly) configurable parser, which understands most of the RFC5321 address format (currently missing are address literals).

Note that this package doesn't deal with UTF8, punycode etc, and
attempting to feed UTF8 characters outside the 32..126 range to the
various functions will result in errors.
