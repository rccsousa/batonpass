defmodule RelayAppWeb.ClipboardSocket do
  @moduledoc """
  Socket transport for clipboard fan-out. CONTRACT.md §1-2.

  The tailnet gate runs at connect, before the socket exists, so a rejected peer
  gets a connection refusal rather than an error frame.
  """

  # log_handled_in/log_join false: Phoenix would otherwise log the frame bytes
  # as "Parameters:" on every message, accumulating ciphertext in the log on the
  # one host this design deliberately distrusts. CONTRACT.md §4.
  use Phoenix.Socket, log: false

  require Logger

  alias RelayApp.Tailnet.Gate

  channel "clipboard:*", RelayAppWeb.ClipboardChannel

  @impl true
  def connect(_params, socket, connect_info) do
    with {:ok, ip} <- peer_ip(connect_info),
         {:ok, identity} <- Gate.authorize(ip) do
      Logger.info("relay: accepted #{identity.name} (#{identity.stable_id})")
      {:ok, assign(socket, :identity, identity)}
    else
      {:error, reason} ->
        Logger.warning("relay: refused peer: #{inspect(reason)}")
        :error
    end
  end

  defp peer_ip(%{peer_data: %{address: address}}) when is_tuple(address) do
    {:ok, address |> :inet.ntoa() |> to_string()}
  end

  defp peer_ip(_), do: {:error, :no_peer_ip}

  @impl true
  def id(socket), do: "peer:#{socket.assigns.identity.stable_id}"
end
