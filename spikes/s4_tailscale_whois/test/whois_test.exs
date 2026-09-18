defmodule S4TailscaleWhois.WhoisTest do
  use ExUnit.Case, async: true

  alias S4TailscaleWhois.Whois

  @sample """
  {"Node":{"ID":100000000000001,"StableID":"nREDACTED02CNTRL",
  "Name":"iphone-example.example.ts.net.","User":100000000000002,
  "Addresses":["100.64.0.30/32"]},
  "UserProfile":{"ID":100000000000002,"LoginName":"owner@example.invalid"}}
  """

  @tagged """
  {"Node":{"StableID":"nREDACTED04CNTRL","Name":"lab.example.ts.net.",
  "Tags":["tag:lab"]},"UserProfile":{"LoginName":"tagged-devices"}}
  """

  test "extracts identity from real whois output" do
    assert {:ok, identity} = Whois.resolve("100.64.0.30", fn _ -> {:ok, @sample} end)
    assert identity.stable_id == "nREDACTED02CNTRL"
    assert identity.login_name == "owner@example.invalid"
    assert identity.tags == []
  end

  test "surfaces tags for a tagged node" do
    assert {:ok, identity} = Whois.resolve("100.64.0.20", fn _ -> {:ok, @tagged} end)
    assert identity.tags == ["tag:lab"]
    assert identity.login_name == "tagged-devices"
  end

  test "rejects a non-IP before it reaches argv" do
    never_called = fn _ -> flunk("resolver must not run on an invalid IP") end

    assert {:error, :invalid_ip} = Whois.resolve("100.1.1.1; rm -rf /", never_called)
    assert {:error, :invalid_ip} = Whois.resolve("$(whoami)", never_called)
    assert {:error, :invalid_ip} = Whois.resolve("", never_called)
  end

  test "rejects output with no StableID" do
    assert {:error, :malformed_whois} =
             Whois.resolve("100.64.0.30", fn _ -> {:ok, "{\"Node\":{}}"} end)
  end

  test "rejects non-JSON output" do
    assert {:error, :malformed_whois} =
             Whois.resolve("100.64.0.30", fn _ -> {:ok, "peer not found"} end)
  end

  @tag :integration
  if is_nil(System.get_env("S4_LIVE_PEER_IP")) do
    @tag skip: "set S4_LIVE_PEER_IP to run against a live tailnet peer"
  end

  test "resolves a real peer against the live tailnet" do
    peer_ip = System.fetch_env!("S4_LIVE_PEER_IP")
    assert {:ok, identity} = Whois.resolve(peer_ip)
    assert identity.stable_id != ""

    if expected_name = System.get_env("S4_LIVE_PEER_NAME") do
      assert identity.name =~ expected_name
    end
  end

  @tag :integration
  test "fails closed on a real non-peer address" do
    assert {:error, :peer_not_found} = Whois.resolve("8.8.8.8")
  end
end
