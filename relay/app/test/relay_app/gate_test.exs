defmodule RelayApp.Tailnet.GateTest do
  use ExUnit.Case, async: false

  alias RelayApp.Tailnet.Gate

  @owner "owner@example.invalid"
  @mac "nREDACTED02CNTRL"
  @windows "nREDACTED03CNTRL"
  @lab "nREDACTED04CNTRL"

  defp identity(id, opts \\ []) do
    %{
      stable_id: id,
      name: Keyword.get(opts, :name, "node.example.ts.net."),
      login_name: Keyword.get(opts, :login, @owner),
      tags: Keyword.get(opts, :tags, [])
    }
  end

  defp configure(resolver, allowed \\ [@mac, @windows]) do
    Application.put_env(:relay_app, :whois_resolver, resolver)
    Application.put_env(:relay_app, :allowed_stable_ids, allowed)
    Application.put_env(:relay_app, :owner_login, @owner)
    on_exit(fn -> Application.delete_env(:relay_app, :whois_resolver) end)
  end

  test "accepts an enrolled, untagged, owner-operated peer" do
    configure(fn _ -> {:ok, identity(@windows)} end)
    assert {:ok, %{stable_id: @windows}} = Gate.authorize("100.64.0.40")
  end

  test "rejects a tagged node even when its StableID is allowlisted" do
    configure(fn _ -> {:ok, identity(@lab, login: "tagged-devices", tags: ["tag:lab"])} end,
      [@mac, @windows, @lab])

    assert {:error, {:tagged_node, ["tag:lab"]}} = Gate.authorize("100.64.0.20")
  end

  test "rejects a peer belonging to another user" do
    configure(fn _ -> {:ok, identity(@windows, login: "colleague@example.com")} end)
    assert {:error, {:foreign_user, _}} = Gate.authorize("100.64.0.40")
  end

  test "rejects a peer that is not enrolled" do
    configure(fn _ -> {:ok, identity("nUNKNOWN111CNTRL")} end)
    assert {:error, {:not_enrolled, _}} = Gate.authorize("100.1.1.1")
  end

  test "fails closed when tailscaled is unavailable" do
    configure(fn _ -> {:error, {:whois_unavailable, :enoent}} end)
    assert {:error, {:whois_unavailable, :enoent}} = Gate.authorize("100.64.0.40")
  end

  test "fails closed when the peer is not in the tailnet" do
    configure(fn _ -> {:error, :peer_not_found} end)
    assert {:error, :peer_not_found} = Gate.authorize("8.8.8.8")
  end

  test "fails closed when the allowlist is empty" do
    configure(fn _ -> {:ok, identity(@windows)} end, [])
    assert {:error, {:not_enrolled, _}} = Gate.authorize("100.64.0.40")
  end
end
