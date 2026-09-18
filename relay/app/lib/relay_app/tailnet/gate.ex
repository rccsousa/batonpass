defmodule RelayApp.Tailnet.Gate do
  @moduledoc """
  Authorization decision for a tailnet peer. CONTRACT.md §2.

  Three independent conditions, all required. Any failure is a refusal,
  including the resolver being unavailable.
  """

  alias RelayApp.Tailnet.Whois

  @spec authorize(String.t()) :: {:ok, Whois.identity()} | {:error, term()}
  def authorize(ip) do
    with {:ok, identity} <- resolver().(ip),
         :ok <- reject_tagged(identity),
         :ok <- require_owner(identity),
         :ok <- require_allowlisted(identity) do
      {:ok, identity}
    end
  end

  defp resolver, do: Application.get_env(:relay_app, :whois_resolver, &Whois.resolve/1)

  # A tagged node is shared infrastructure. The lab server carries tag:lab and
  # resolves to the "tagged-devices" pseudo-user, so this is structural rather
  # than a naming convention anyone has to maintain.
  #
  # Checked before the allowlist deliberately: a mis-enrolled tagged node still fails.
  defp reject_tagged(%{tags: []}), do: :ok
  defp reject_tagged(%{tags: tags}), do: {:error, {:tagged_node, tags}}

  defp require_owner(%{login_name: login}) do
    case Application.get_env(:relay_app, :owner_login) do
      ^login -> :ok
      nil -> {:error, :owner_login_unset}
      _ -> {:error, {:foreign_user, login}}
    end
  end

  defp require_allowlisted(%{stable_id: id}) do
    allowed = Application.get_env(:relay_app, :allowed_stable_ids, [])
    if id in allowed, do: :ok, else: {:error, {:not_enrolled, id}}
  end
end
