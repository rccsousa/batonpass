defmodule RelayAppWeb.ClipboardChannel do
  @moduledoc """
  Opaque ciphertext fan-out. CONTRACT.md §1, §3, §5.

  Never parses an envelope beyond its length. No version byte, no epoch, no
  sender, no timestamp: those belong to receivers, which hold keys. This moves
  bytes.
  """

  use Phoenix.Channel, log_handle_in: false, log_join: false

  require Logger

  alias RelayApp.Topics

  @min_frame 61
  @max_frame 65_597
  @max_frames_per_sec 20
  @max_subscribers 16

  @impl true
  def join("clipboard:" <> group_id = topic, _params, socket) do
    cond do
      not String.match?(group_id, ~r/^[A-Za-z0-9_-]{1,64}$/) ->
        {:error, %{reason: "bad_group"}}

      Topics.count(topic) >= @max_subscribers ->
        Logger.warning("relay: refused join, topic full")
        {:error, %{reason: "topic_full"}}

      true ->
        Topics.join(topic, self())
        {:ok, assign(socket, :rate, {System.monotonic_time(:second), 0})}
    end
  end

  @impl true
  def handle_in("frame", {:binary, frame}, socket) do
    with :ok <- check_size(frame),
         {:ok, socket} <- check_rate(socket) do
      # broadcast_from! excludes the sender. CONTRACT §5: never echo.
      broadcast_from!(socket, "frame", {:binary, frame})
      {:noreply, socket}
    else
      {:error, reason} ->
        # Size is metadata and is safe to log. The frame itself never is.
        Logger.warning(
          "relay: closing #{peer(socket)}: #{inspect(reason)} (frame size #{byte_size(frame)})"
        )

        {:stop, :normal, socket}
    end
  end

  def handle_in("frame", _other, socket) do
    Logger.warning("relay: closing #{peer(socket)}: non_binary_frame")
    {:stop, :normal, socket}
  end

  @impl true
  def terminate(_reason, socket) do
    Topics.leave(socket.topic, self())
    :ok
  end

  defp check_size(frame) when byte_size(frame) < @min_frame, do: {:error, :frame_too_small}
  defp check_size(frame) when byte_size(frame) > @max_frame, do: {:error, :frame_too_large}
  defp check_size(_), do: :ok

  defp check_rate(socket) do
    now = System.monotonic_time(:second)

    case socket.assigns.rate do
      {^now, n} when n >= @max_frames_per_sec -> {:error, :rate_exceeded}
      {^now, n} -> {:ok, assign(socket, :rate, {now, n + 1})}
      _ -> {:ok, assign(socket, :rate, {now, 1})}
    end
  end

  defp peer(socket), do: socket.assigns.identity.stable_id
end
