defmodule MailAddress.MixProject do
  use Mix.Project

  def project do
    [
      app: :mail_address,
      version: "0.1.0",
      elixir: "~> 1.6",
      package: package(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: [
        plt_add_deps: :transitive,
        flags: [:unmatched_returns, :race_conditions, :error_handling, :underspecs],
        ignore_warnings: ".dialyzer_ignore"
      ],
      docs: [
        main: "MailAddress",
        extras: ["README.md"]
      ],
      name: "MailAddress"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, ">= 0.8.0", only: :dev, runtime: false},
      {:dialyxir, ">= 0.5.0", only: :dev, runtime: false},
      {:ex_doc, "~> 0.18", only: [:dev, :docs], runtime: false}
    ]
  end

  defp github do
    "https://github.com/john-vinters/mail_address"
  end

  defp package do
    [
      name: "mail_address",
      maintainers: ["John Vinters"],
      licenses: ["MIT"],
      links: %{"GitHub" => github()}
    ]
  end
end