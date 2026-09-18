defmodule S4TailscaleWhois.Plug do
  @moduledoc """
  Rejects any connection whose tailnet identity is not on an explicit allowlist.

  Fails closed. Every path that does not end in a positively resolved,
  explicitly allowlisted, untagged peer results in 403.
  """

  import Plug.Conn

  alias S4TailscaleWhois.Whois

  @behaviour Plug

  @impl true
  def init(opts) do
    %{
      allowed: Keyword.fetch!(opts, :allowed_stable_ids) |> MapSet.new(),
      owner: Keyword.fetch!(opts, :owner_login),
      resolver: Keyword.get(opts, :resolver, &Whois.resolve/1)
    }
  end

  @impl true
  def call(conn, opts) do
    case authorize(conn, opts) do
      {:ok, identity} -> assign(conn, :tailnet_identity, identity)
      {:error, reason} -> deny(conn, reason)
    end
  end

  defp authorize(conn, opts) do
    with {:ok, ip} <- peer_ip(conn),
         {:ok, identity} <- opts.resolver.(ip),
         :ok <- reject_tagged(identity),
         :ok <- require_owner(identity, opts.owner),
         :ok <- require_allowlisted(identity, opts.allowed) do
      {:ok, identity}
    end
  end

  defp peer_ip(%Plug.Conn{remote_ip: remote_ip}) when is_tuple(remote_ip) do
    {:ok, remote_ip |> :inet.ntoa() |> to_string()}
  end

  defp peer_ip(_), do: {:error, :no_peer_ip}

  # A tagged node is shared infrastructure, not a personal device. The lab
  # server carries tag:lab and resolves to the "tagged-devices" pseudo-user,
  # so tags are a reliable structural signal rather than a naming convention.
  defp reject_tagged(%{tags: []}), do: :ok
  defp reject_tagged(%{tags: tags}) when is_list(tags), do: {:error, {:tagged_node, tags}}

  defp require_owner(%{login_name: login}, owner) when login == owner, do: :ok
  defp require_owner(%{login_name: login}, _owner), do: {:error, {:foreign_user, login}}

  defp require_allowlisted(%{stable_id: id}, allowed) do
    if MapSet.member?(allowed, id), do: :ok, else: {:error, {:not_enrolled, id}}
  end

  defp deny(conn, reason) do
    # Identity metadata only. Never log request bodies here.
    require Logger
    Logger.warning("batonpass: rejected peer: #{inspect(reason)}")

    conn
    |> send_resp(403, "forbidden")
    |> halt()
  end
end
