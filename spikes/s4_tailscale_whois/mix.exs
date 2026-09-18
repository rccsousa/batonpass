defmodule S4TailscaleWhois.MixProject do
  use Mix.Project

  def project do
    [
      app: :s4_tailscale_whois,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {S4TailscaleWhois.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.16"},
      {:jason, "~> 1.4"}
    ]
  end
end
