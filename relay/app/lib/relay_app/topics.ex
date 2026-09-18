defmodule RelayApp.Topics do
  @moduledoc """
  Subscriber counts per topic, for the cap in CONTRACT.md §3.

  Phoenix.PubSub exposes no supported way to count subscribers on a topic, so
  joins and departures are tracked here. Monitors handle the case where a
  channel process dies without calling `leave/1`.
  """

  use GenServer

  @table __MODULE__

  def start_link(opts), do: GenServer.start_link(__MODULE__, :ok, Keyword.put(opts, :name, __MODULE__))

  @spec count(String.t()) :: non_neg_integer()
  def count(topic) do
    case :ets.lookup(@table, topic) do
      [{^topic, n}] -> n
      [] -> 0
    end
  end

  @spec join(String.t(), pid()) :: :ok
  def join(topic, pid), do: GenServer.call(__MODULE__, {:join, topic, pid})

  @spec leave(String.t(), pid()) :: :ok
  def leave(topic, pid), do: GenServer.cast(__MODULE__, {:leave, topic, pid})

  @impl true
  def init(:ok) do
    :ets.new(@table, [:named_table, :set, :protected, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_call({:join, topic, pid}, _from, refs) do
    ref = Process.monitor(pid)
    :ets.update_counter(@table, topic, {2, 1}, {topic, 0})
    {:reply, :ok, Map.put(refs, ref, {topic, pid})}
  end

  @impl true
  def handle_cast({:leave, topic, pid}, refs) do
    {:noreply, drop(refs, topic, pid)}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, refs) do
    case Map.pop(refs, ref) do
      {nil, refs} -> {:noreply, refs}
      {{topic, _pid}, refs} -> {:noreply, decrement(topic, refs)}
    end
  end

  defp drop(refs, topic, pid) do
    case Enum.find(refs, fn {_ref, v} -> v == {topic, pid} end) do
      nil ->
        refs

      {ref, _} ->
        Process.demonitor(ref, [:flush])
        refs |> Map.delete(ref) |> then(&decrement(topic, &1))
    end
  end

  defp decrement(topic, refs) do
    if :ets.update_counter(@table, topic, {2, -1, 0, 0}, {topic, 0}) == 0 do
      :ets.delete(@table, topic)
    end

    refs
  end
end
