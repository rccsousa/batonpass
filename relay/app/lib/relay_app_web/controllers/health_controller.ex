defmodule RelayAppWeb.HealthController do
  @moduledoc """
  CONTRACT.md §6. Metadata only: never a frame, never a count of anything
  derived from frame contents.
  """

  use RelayAppWeb, :controller

  alias RelayApp.Tailnet.Gate
  alias RelayApp.Topics

  def show(conn, _params) do
    # Subject to the same allowlist as the socket: the relay must not disclose
    # who is connected to a peer that is not itself enrolled.
    case authorize(conn) do
      {:ok, identity} ->
        json(conn, %{
          status: "ok",
          version: Application.spec(:relay_app, :vsn) |> to_string(),
          peer: identity.name,
          subscribers: Topics.count("clipboard:" <> group(conn))
        })

      {:error, reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{status: "forbidden", reason: inspect(reason)})
    end
  end

  defp authorize(%Plug.Conn{remote_ip: ip}) when is_tuple(ip) do
    ip |> :inet.ntoa() |> to_string() |> Gate.authorize()
  end

  defp authorize(_), do: {:error, :no_peer_ip}

  defp group(conn) do
    case conn.query_params["group"] do
      g when is_binary(g) -> if String.match?(g, ~r/^[A-Za-z0-9_-]{1,64}$/), do: g, else: "home"
      _ -> "home"
    end
  end
end
