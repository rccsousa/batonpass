defmodule S4TailscaleWhois.Whois do
  @moduledoc """
  Resolves a tailnet source IP to a tailnet identity via `tailscale whois`.

  Returns `{:ok, identity}` only when the peer is unambiguously resolved.
  Every other outcome is an error: unresolvable, daemon down, malformed
  output, or a peer that is not in the tailnet at all.
  """

  @type identity :: %{
          stable_id: String.t(),
          name: String.t(),
          login_name: String.t(),
          tags: [String.t()]
        }

  @tailscale "/Applications/Tailscale.app/Contents/MacOS/Tailscale"

  @doc """
  `resolve/2` shells out to `tailscale whois --json`.

  `runner` is injectable so tests can simulate a downed daemon without
  stopping the real one.
  """
  @spec resolve(String.t(), (String.t() -> {:ok, String.t()} | {:error, term()})) ::
          {:ok, identity()} | {:error, atom()}
  def resolve(ip, runner \\ &run_whois/1) do
    with :ok <- validate_ip(ip),
         {:ok, json} <- runner.(ip),
         {:ok, decoded} <- decode(json),
         {:ok, identity} <- extract(decoded) do
      {:ok, identity}
    end
  end

  # An IP reaches argv, so reject anything that is not a bare address before
  # it gets there. Belt and braces: argv already prevents shell interpretation.
  defp validate_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :invalid_ip}
    end
  end

  defp validate_ip(_), do: {:error, :invalid_ip}

  defp run_whois(ip) do
    case System.cmd(@tailscale, ["whois", "--json", ip], stderr_to_stdout: false) do
      {out, 0} -> {:ok, out}
      {_, _nonzero} -> {:error, :peer_not_found}
    end
  rescue
    # tailscaled absent or binary missing: fail closed, never fall through.
    e in ErlangError -> {:error, {:whois_unavailable, e.original}}
  end

  defp decode(json) do
    case Jason.decode(json) do
      {:ok, %{} = map} -> {:ok, map}
      _ -> {:error, :malformed_whois}
    end
  end

  defp extract(%{"Node" => node} = decoded) do
    stable_id = node["StableID"]

    if is_binary(stable_id) and stable_id != "" do
      {:ok,
       %{
         stable_id: stable_id,
         name: node["Name"] || "",
         login_name: get_in(decoded, ["UserProfile", "LoginName"]) || "",
         tags: node["Tags"] || []
       }}
    else
      {:error, :malformed_whois}
    end
  end

  defp extract(_), do: {:error, :malformed_whois}
end
