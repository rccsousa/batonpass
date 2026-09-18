defmodule RelayAppWeb.HealthTest do
  @moduledoc """
  CONTRACT.md §6 promised this endpoint and the relay did not have it — found by
  the Windows agent hitting it from `windows-pc` and getting NoRouteError.
  """

  use RelayAppWeb.ConnCase, async: false

  @owner "owner@example.com"

  setup do
    Application.put_env(:relay_app, :owner_login, @owner)
    on_exit(fn -> Application.delete_env(:relay_app, :whois_resolver) end)
    :ok
  end

  defp allow(identity, allowed) do
    Application.put_env(:relay_app, :whois_resolver, fn _ip -> {:ok, identity} end)
    Application.put_env(:relay_app, :allowed_stable_ids, allowed)
  end

  test "returns metadata to an enrolled peer", %{conn: conn} do
    allow(%{stable_id: "nOK", name: "mac.ts.net.", login_name: @owner, tags: []}, ["nOK"])

    body = conn |> get("/health") |> json_response(200)

    assert body["status"] == "ok"
    assert body["peer"] == "mac.ts.net."
    assert is_integer(body["subscribers"])
  end

  test "refuses a peer that is not enrolled", %{conn: conn} do
    allow(%{stable_id: "nNOPE", name: "other.ts.net.", login_name: @owner, tags: []}, ["nOK"])

    assert conn |> get("/health") |> json_response(403)
  end

  test "refuses a tagged node" do
    allow(%{stable_id: "nLAB", name: "lab.ts.net.", login_name: "tagged-devices", tags: ["tag:lab"]},
      ["nLAB"])

    assert Phoenix.ConnTest.build_conn() |> get("/health") |> json_response(403)
  end

  test "fails closed when the resolver is unavailable", %{conn: conn} do
    Application.put_env(:relay_app, :whois_resolver, fn _ -> {:error, {:whois_unavailable, :enoent}} end)

    assert conn |> get("/health") |> json_response(403)
  end
end
