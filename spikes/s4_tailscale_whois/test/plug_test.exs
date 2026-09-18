defmodule S4TailscaleWhois.PlugTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias S4TailscaleWhois.Plug, as: Gate

  @owner "owner@example.invalid"

  # Real StableIDs observed on the tailnet, so the fixtures match production shape.
  @mac "nREDACTED02CNTRL"
  @windows "nREDACTED03CNTRL"
  @lab "nREDACTED04CNTRL"

  defp identity(stable_id, opts \\ []) do
    %{
      stable_id: stable_id,
      name: Keyword.get(opts, :name, "node.example.ts.net."),
      login_name: Keyword.get(opts, :login, @owner),
      tags: Keyword.get(opts, :tags, [])
    }
  end

  defp gate(resolver, allowed \\ [@mac, @windows]) do
    Gate.init(allowed_stable_ids: allowed, owner_login: @owner, resolver: resolver)
  end

  defp call(opts, ip \\ {100, 104, 229, 57}) do
    :get
    |> conn("/")
    |> Map.put(:remote_ip, ip)
    |> Gate.call(opts)
  end

  describe "allows" do
    test "an enrolled, untagged, owner-operated peer" do
      conn = call(gate(fn _ip -> {:ok, identity(@windows)} end))

      refute conn.halted
      assert conn.assigns.tailnet_identity.stable_id == @windows
    end
  end

  describe "fails closed" do
    test "when the peer is not on the allowlist" do
      conn = call(gate(fn _ip -> {:ok, identity("nUNKNOWN111CNTRL")} end))

      assert conn.halted
      assert conn.status == 403
    end

    test "when the node is tagged, even if the StableID is allowlisted" do
      resolver = fn _ip -> {:ok, identity(@lab, login: "tagged-devices", tags: ["tag:lab"])} end
      conn = call(gate(resolver, [@mac, @windows, @lab]))

      assert conn.halted
      assert conn.status == 403
    end

    test "when the peer belongs to another user" do
      resolver = fn _ip -> {:ok, identity(@windows, login: "colleague@example.com")} end
      conn = call(gate(resolver))

      assert conn.halted
      assert conn.status == 403
    end

    test "when tailscaled is down" do
      resolver = fn _ip -> {:error, {:whois_unavailable, :enoent}} end
      conn = call(gate(resolver))

      assert conn.halted
      assert conn.status == 403
    end

    test "when the peer is not in the tailnet" do
      resolver = fn _ip -> {:error, :peer_not_found} end
      conn = call(gate(resolver))

      assert conn.halted
      assert conn.status == 403
    end

    test "when whois returns malformed output" do
      resolver = fn _ip -> {:error, :malformed_whois} end
      conn = call(gate(resolver))

      assert conn.halted
      assert conn.status == 403
    end

    test "when the allowlist is empty" do
      conn = call(gate(fn _ip -> {:ok, identity(@windows)} end, []))

      assert conn.halted
      assert conn.status == 403
    end

    test "when the resolver raises" do
      resolver = fn _ip -> raise "tailscaled exploded" end

      assert_raise RuntimeError, fn ->
        call(gate(resolver))
      end
    end
  end
end
