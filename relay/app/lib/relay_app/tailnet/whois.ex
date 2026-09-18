defmodule RelayApp.Tailnet.Whois do
  @moduledoc """
  Resolves a tailnet source IP to a tailnet identity.

  Returns `{:ok, identity}` only for an unambiguously resolved peer. Every other
  outcome — unresolvable, daemon down, malformed output, not in the tailnet — is
  an error. Callers must fail closed on all of them.
  """

  require Logger

  @type identity :: %{
          stable_id: String.t(),
          name: String.t(),
          login_name: String.t(),
          tags: [String.t()]
        }

  @spec resolve(String.t()) :: {:ok, identity()} | {:error, term()}
  def resolve(ip), do: resolve(ip, &run/1)

  @doc "`runner` is injectable so tests can simulate a downed daemon."
  @spec resolve(String.t(), (String.t() -> {:ok, String.t()} | {:error, term()})) ::
          {:ok, identity()} | {:error, term()}
  def resolve(ip, runner) do
    with :ok <- validate_ip(ip),
         {:ok, json} <- runner.(ip),
         {:ok, decoded} <- decode(json) do
      extract(decoded)
    end
  end

  # The IP reaches argv, so reject anything that is not a bare address before it
  # gets there. argv already prevents shell interpretation; this is the second lock.
  defp validate_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :invalid_ip}
    end
  end

  defp validate_ip(_), do: {:error, :invalid_ip}

  defp run(ip) do
    bin = Application.get_env(:relay_app, :tailscale_bin, "tailscale")

    case System.cmd(bin, ["whois", "--json", ip], stderr_to_stdout: false) do
      {out, 0} -> {:ok, out}
      {_, _} -> {:error, :peer_not_found}
    end
  rescue
    # Binary missing or tailscaled unreachable. Never fall through to allow.
    e in ErlangError -> {:error, {:whois_unavailable, e.original}}
  end

  defp decode(json) do
    case Jason.decode(json) do
      {:ok, %{} = map} -> {:ok, map}
      _ -> {:error, :malformed_whois}
    end
  end

  defp extract(%{"Node" => node} = decoded) do
    case node["StableID"] do
      id when is_binary(id) and id != "" ->
        {:ok,
         %{
           stable_id: id,
           name: node["Name"] || "",
           login_name: get_in(decoded, ["UserProfile", "LoginName"]) || "",
           tags: node["Tags"] || []
         }}

      _ ->
        {:error, :malformed_whois}
    end
  end

  defp extract(_), do: {:error, :malformed_whois}
end
