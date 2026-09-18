defmodule RelayAppWeb.ClipboardChannelTest do
  use RelayAppWeb.ChannelCase, async: false

  alias RelayAppWeb.ClipboardChannel

  @identity %{
    stable_id: "nTESTPEER01CNTRL",
    name: "test.example.ts.net.",
    login_name: "owner@example.com",
    tags: []
  }

  defp connect(id \\ @identity) do
    RelayAppWeb.ClipboardSocket
    |> socket("peer:#{id.stable_id}", %{identity: id})
  end

  defp frame(size), do: :crypto.strong_rand_bytes(size)

  describe "join" do
    test "accepts a well-formed group" do
      assert {:ok, _, _socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
    end

    test "rejects a malformed group id" do
      assert {:error, %{reason: "bad_group"}} =
               subscribe_and_join(connect(), ClipboardChannel, "clipboard:has spaces")
    end
  end

  describe "frame size limits" do
    test "accepts a minimum-size frame" do
      {:ok, _, socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      ref = Process.monitor(socket.channel_pid)
      push(socket, "frame", {:binary, frame(61)})
      refute_receive {:DOWN, ^ref, _, _, _}, 100
    end

    test "closes the connection on a frame below the minimum" do
      {:ok, _, socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      ref = Process.monitor(socket.channel_pid)
      push(socket, "frame", {:binary, frame(60)})
      assert_receive {:DOWN, ^ref, _, _, _}, 500
    end

    test "closes the connection on a frame above the maximum" do
      {:ok, _, socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      ref = Process.monitor(socket.channel_pid)
      push(socket, "frame", {:binary, frame(65_598)})
      assert_receive {:DOWN, ^ref, _, _, _}, 500
    end

    test "accepts a maximum-size frame" do
      {:ok, _, socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      ref = Process.monitor(socket.channel_pid)
      push(socket, "frame", {:binary, frame(65_597)})
      refute_receive {:DOWN, ^ref, _, _, _}, 100
    end

    test "closes the connection on a non-binary payload" do
      {:ok, _, socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      ref = Process.monitor(socket.channel_pid)
      push(socket, "frame", %{"not" => "binary"})
      assert_receive {:DOWN, ^ref, _, _, _}, 500
    end
  end

  describe "fan-out" do
    test "broadcasts to other subscribers" do
      {:ok, _, a} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      payload = frame(100)
      push(a, "frame", {:binary, payload})
      assert_broadcast "frame", {:binary, ^payload}
    end

    test "never echoes to the sender" do
      {:ok, _, a} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      push(a, "frame", {:binary, frame(100)})
      refute_push "frame", _any
    end
  end

  describe "rate limiting" do
    test "closes the connection past the per-second cap" do
      {:ok, _, socket} = subscribe_and_join(connect(), ClipboardChannel, "clipboard:home")
      ref = Process.monitor(socket.channel_pid)
      for _ <- 1..25, do: push(socket, "frame", {:binary, frame(61)})
      assert_receive {:DOWN, ^ref, _, _, _}, 1000
    end
  end
end
