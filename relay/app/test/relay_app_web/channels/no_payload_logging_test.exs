defmodule RelayAppWeb.NoPayloadLoggingTest do
  @moduledoc """
  CONTRACT.md §4: frame bytes must never reach a log, including via Phoenix's own
  channel instrumentation. This caught a real leak — Phoenix logs the full binary
  payload as "Parameters:" on every handle_in unless log_handle_in is disabled.
  """

  use RelayAppWeb.ChannelCase, async: false

  import ExUnit.CaptureLog

  alias RelayAppWeb.ClipboardChannel

  @identity %{
    stable_id: "nTESTPEER01CNTRL",
    name: "test.example.ts.net.",
    login_name: "owner@example.com",
    tags: []
  }

  test "no part of a frame appears in the log" do
    # A recognisable run of bytes: if any slice reaches the log, the inspect form
    # of these will show up.
    marker = :binary.copy(<<222, 173, 190, 239>>, 4)
    frame = marker <> :crypto.strong_rand_bytes(100 - byte_size(marker))

    log =
      capture_log(fn ->
        socket = socket(RelayAppWeb.ClipboardSocket, "peer:x", %{identity: @identity})
        {:ok, _, socket} = subscribe_and_join(socket, ClipboardChannel, "clipboard:home")
        push(socket, "frame", {:binary, frame})
        Process.sleep(50)
      end)

    refute log =~ "222, 173, 190, 239"
    refute log =~ "deadbeef"
    refute log =~ "Parameters"
  end
end
